rule PEiD_00612_EXECryptor_2_2_2_3__compressed_code_____www_strongbit_com_ {
  meta:
    description = "[EXECryptor 2.2/2.3 (compressed code) -> www.strongbit.com]"
    ep_only     = "true"

  strings:
    $a = { E8 00 00 00 00 58 ?? ?? ?? ?? ?? 8B 1C 24 81 EB ?? ?? ?? ?? B8 ?? ?? ?? ?? 50 6A 04 68 00 10 00 00 50 6A 00 B8 C4 ?? ?? ?? 8B 04 18 FF D0 59 BA ?? ?? ?? ?? 01 DA 52 53 50 89 C7 89 D6 FC F3 A4 B9 ?? ?? ?? ?? 01 D9 FF D1 58 8B 1C 24 68 00 80 00 00 6A 00 50 }

  condition:
    $a
}