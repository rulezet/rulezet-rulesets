rule _20160921_06311313c2c91f30b188be9b0f27e37d_20160921_4a2d69f96df0_4259 {
  meta:
    description = "datamaliciousorder - from files 20160921_06311313c2c91f30b188be9b0f27e37d.js, 20160921_4a2d69f96df0dd4c57fda9e63c804950.js, 20160921_619a314e9bcca286c046dff250b54b6b.js, 20160922_92c62e47426236a3598469915ee3dcfe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e8ad2d8de7bc2cc77c2b00b8eeb4fd7976cd68790eeb4b6bfd14ad188696ed0"
    hash2       = "786d4a5233f100c1ba7f5e820c46309247158a45ed43bd58795f05152dbaecf6"
    hash3       = "9f370548310908c52102d40d56781574ad404eafca7ac832d5e52d48f722bff5"
    hash4       = "d6b6eb713cecae41143fb04e090a4809564a1837f49e53a84e27f0d3b0885df7"

  strings:
    $s1 = "),(function f000(){return \"WIj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Vj\";})(),(function f000(){" ascii
    $s2 = "\"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"RPt\";})(),(funct" ascii
    $s3 = "rn \"KDh\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s4 = "t\";})(),(function f000(){return \"KZr\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MKa\";})(),(function" ascii
    $s5 = "on f000(){return \"ZFe\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}