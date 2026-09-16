rule _20160921_2746dcb029094ed409681059b0bf7b68_20160921_582a5b9e6263_14 {
  meta:
    description = "datamaliciousorder - from files 20160921_2746dcb029094ed409681059b0bf7b68.js, 20160921_582a5b9e6263457a7095e1d0bf6ab96b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9908788e148928c5f3ee88b22ad1ed33dbf69f1ffd103491ebd438b979bb77eb"
    hash2       = "ef65e5e7f2b9ad6a0714382fda8dc9fde658333c4a3ea2cdf04558bfe763c3b6"

  strings:
    $s1  = "n f000(){return \"Oh\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TR" ascii
    $s2  = ";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Yz\";})(),(function f00" ascii
    $s3  = " f000(){return \"ZIi\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"T" ascii
    $s4  = "function f000(){return \"PTs\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Lo\";})(),(function f000(){ret" ascii
    $s5  = "\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qa\";})(),(function " ascii
    $s6  = "o\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(functio" ascii
    $s7  = "turn \"TKl\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TRc\";})()" ascii
    $s8  = "00(){return \"ZFe\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"RPt" ascii
    $s9  = "n f000(){return \"ZFe\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii
    $s10 = "{return \"OUx\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"XTn\";})" ascii
    $s11 = "00(){return \"MJq\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"PTi" ascii
    $s12 = "){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Km\";})(" ascii
    $s13 = "rn \"EZu\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s14 = "0(){return \"OUx\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"KXg\"" ascii
    $s15 = "return \"RPt\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(" ascii
    $s16 = "eturn \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"SGs\";})()" ascii
    $s17 = "\"OUx\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(funct" ascii
    $s18 = "(){return \"DNa\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"WIj\";" ascii
    $s19 = "000(){return \"Do\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn" ascii
    $s20 = ";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"TRc\";})(),(function f00" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}