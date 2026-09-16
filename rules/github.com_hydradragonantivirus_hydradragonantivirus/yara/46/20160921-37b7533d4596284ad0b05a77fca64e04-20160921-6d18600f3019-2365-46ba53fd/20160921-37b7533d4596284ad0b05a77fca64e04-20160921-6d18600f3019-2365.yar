rule _20160921_37b7533d4596284ad0b05a77fca64e04_20160921_6d18600f3019_2365 {
  meta:
    description = "datamaliciousorder - from files 20160921_37b7533d4596284ad0b05a77fca64e04.js, 20160921_6d18600f3019656b0ab414a3d1a69ddb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "61b41be208c77057ce2b56a866ae0e936c6372d0c3a92f126a1cf5090fe0a5e7"
    hash2       = "fb0471dc4828588d37d01ddaa7b9454e82acacc4dfdd9f0998b461661e3810db"

  strings:
    $s1 = "tion f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"ZIi\";})(),(function f000(){retur" ascii
    $s2 = "function f000(){return \"OUx\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Vu\";})(),(function f000(){ret" ascii
    $s3 = "eturn \"Vj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})()" ascii
    $s4 = "00(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Nx\"" ascii
    $s5 = "GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s6 = "on f000(){return \"GGn\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s7 = ";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Vj\";})(),(function f000" ascii
    $s8 = "{return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"Ut\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}