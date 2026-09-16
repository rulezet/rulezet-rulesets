rule _20160921_619a314e9bcca286c046dff250b54b6b_20160921_6ad2178e7d04_5302 {
  meta:
    description = "datamaliciousorder - from files 20160921_619a314e9bcca286c046dff250b54b6b.js, 20160921_6ad2178e7d047e60c71f9fe1ca457b74.js, 20160921_814eb57aeffc75442964829345cc9f96.js, 20160921_89a260f4d6da4d97f251f843cf5e94b0.js, 20160921_acebc8ac4559526a5a8de801968bd19f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f370548310908c52102d40d56781574ad404eafca7ac832d5e52d48f722bff5"
    hash2       = "2e126f3a35c3e15739f44a3b15bf991678bc6c232e213be738a2521187bf8173"
    hash3       = "2736df4d651a33824aba7abffa7c08414414ffed9f5f27b4b2d81101cfeb7117"
    hash4       = "700f6c802eb024896efe2b22255973b53752a8f129213c9bba2c4f2ebdc53988"
    hash5       = "79fe55ec3d2d6dbd854df9676c4565b6a8410e1d94298c2ff2f112036fcfac73"

  strings:
    $s1 = "Fe\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function " ascii
    $s2 = "00(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc" ascii
    $s3 = " \"KDh\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"ZFe\";})(),(fun" ascii
    $s4 = "),(function f000(){return \"RPt\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TKl\";})(),(function f000()" ascii
    $s5 = "})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vj\";})(),(function f00" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}