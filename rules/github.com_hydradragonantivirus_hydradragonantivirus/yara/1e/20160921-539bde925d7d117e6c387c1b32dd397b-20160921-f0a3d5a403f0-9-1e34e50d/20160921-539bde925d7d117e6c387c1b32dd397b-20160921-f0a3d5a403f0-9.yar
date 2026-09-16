rule _20160921_539bde925d7d117e6c387c1b32dd397b_20160921_f0a3d5a403f0_9 {
  meta:
    description = "datamaliciousorder - from files 20160921_539bde925d7d117e6c387c1b32dd397b.js, 20160921_f0a3d5a403f0d7386ada786b887a464d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ff498e6534ca553e55771f7eceb4682e639590da978950f1c8683f05f448427"
    hash2       = "77a7ef76313303139cf36ae2953c6c901152f97fe8ddc013a16c1d4b69e5357c"

  strings:
    $s1  = "on f000(){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"" ascii
    $s2  = "0(){return \"TKp\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Sv\";" ascii
    $s3  = "(){return \"RPt\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Zj\";" ascii
    $s4  = "urn \"BMj\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"TRc\";})(),(" ascii
    $s5  = " f000(){return \"Vj\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"WI" ascii
    $s6  = "{return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qz\";})(" ascii
    $s7  = "return \"Oh\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\";})(" ascii
    $s8  = "urn \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Vu\";})(),(" ascii
    $s9  = "urn \"ZFe\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"ZFe\";})(),(" ascii
    $s10 = "{return \"Mu\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"KXg\";})" ascii
    $s11 = ",(function f000(){return \"KXg\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"GGn\";})(),(function f000(){" ascii
    $s12 = "\"Sj\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(functi" ascii
    $s13 = "unction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){ret" ascii
    $s14 = "(){return \"DNa\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Oh\";}" ascii
    $s15 = "),(function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"IAa\";})(),(function f000(" ascii
    $s16 = "0(){return \"Yz\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";" ascii
    $s17 = "tion f000(){return \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Wy\";})(),(function f000(){return" ascii
    $s18 = "turn \"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Yz\";})(),(" ascii
    $s19 = "unction f000(){return \"MBb\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"QDg\";})(),(function f000(){ret" ascii
    $s20 = ",(function f000(){return \"Yv\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\";})(),(function f000(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}