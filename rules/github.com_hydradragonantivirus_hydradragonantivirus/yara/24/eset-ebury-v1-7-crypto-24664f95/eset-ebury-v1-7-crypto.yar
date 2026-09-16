rule ESET_Ebury_V1_7_Crypto {
  meta:
    description = "This rule detects the strings decryption routine in Ebury v1.7 and v1.8"
    author      = "ESET, spol. s r.o."
    id          = "93dadf5f-b572-5217-8c82-4957c6d24955"
    date        = "2023-08-01"
    modified    = "2024-04-29"
    reference   = "https://github.com/eset/malware-ioc/"
    source_url  = "https://github.com/eset/malware-ioc/blob/21381c70ad030105cf9edb092dfd1cae29753286/windigo/ebury.yar#L56-L97"
    license_url = "https://github.com/eset/malware-ioc/blob/21381c70ad030105cf9edb092dfd1cae29753286/LICENSE"
    hash        = "e7debd6e453192ad8376db5bab03ed0d87566591"
    logic_hash  = "41908951069a472d7528f2f228f3681f008d16a0436e341d339909efc4933e66"
    score       = 75
    quality     = 80
    tags        = ""
    license     = "BSD 2-Clause"
    version     = 1

  strings:
    $64 = {
      48 69 (9C 24 ?? ?? ?? ?? | 5C 24 ?? | D2) 6D 4E C6 41        8B (0C 16 | 34 07)                                           48 81 C? 39 30 00 00                                         (31 D? |                                                     31 D? 48 89 9C 24 ?? ?? ?? ?? |                              31 D? 48 89 5C 24 ??)                                        89 (0C 10 | 34 01)                                           48 83 C? 04                                                  48 (81 FA | 3D) ?? ?? ?? ??                                  75 D?                                                      }
    $32 = {
      69 C9 6D 4E C6 41           8B B4 1A ?? ?? ?? ??        81 C1 39 30 00 00           31 CE                       89 34 10                    83 C2 04                    81 FA ?? ?? ?? ??           75 DD                     }

  condition:
    any of them
}