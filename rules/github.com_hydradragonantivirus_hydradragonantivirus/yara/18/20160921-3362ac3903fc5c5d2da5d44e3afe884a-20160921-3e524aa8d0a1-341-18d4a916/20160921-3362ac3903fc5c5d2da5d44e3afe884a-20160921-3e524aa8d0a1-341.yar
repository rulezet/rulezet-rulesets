rule _20160921_3362ac3903fc5c5d2da5d44e3afe884a_20160921_3e524aa8d0a1_341 {
  meta:
    description = "datamaliciousorder - from files 20160921_3362ac3903fc5c5d2da5d44e3afe884a.js, 20160921_3e524aa8d0a18c87370a789c7bba4fc5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "923e3ebc3e8bab3120c507f019cac28dec05009a69ab441bfb8be6f7f1a4d258"
    hash2       = "71a83b86275cb43222066a6d27dfb98cdd9fc8283b2b007f9262c38686262b9a"

  strings:
    $s1  = ",(function f000(){return \"Qj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"XTn\";})(),(function f000(){r" ascii
    $s2  = "eturn \"Yi\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})()," ascii
    $s3  = "urn \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(),(f" ascii
    $s4  = "(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"XTn\";" ascii
    $s5  = "on f000(){return \"WIj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"" ascii
    $s6  = "turn \"Qj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Kw\";})(),(" ascii
    $s7  = "eturn \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Lp\";})(),(" ascii
    $s8  = "on f000(){return \"WIj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"" ascii
    $s9  = "f000(){return \"Qz\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Lp" ascii
    $s10 = ",(function f000(){return \"Wb\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"DIa\";})(),(function f000(){r" ascii
    $s11 = "00(){return \"GGn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Do\"" ascii
    $s12 = "\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Kw\";})(),(function f" ascii
    $s13 = "on f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return " ascii
    $s14 = "turn \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})()" ascii
    $s15 = "GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qz\";})(),(functi" ascii
    $s16 = "unction f000(){return \"Lp\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(function f000(){retur" ascii
    $s17 = "rn \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"ZIi\";})(),(f" ascii
    $s18 = "ction f000(){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qj\";})(),(function f000(){return" ascii
    $s19 = " \"Do\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(fun" ascii
    $s20 = "Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qj\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}