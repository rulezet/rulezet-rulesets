rule sig_20160907_d634399ab1ad514c79fa5ba907e203cf {
  meta:
    description = "datamaliciousorder - file 20160907_d634399ab1ad514c79fa5ba907e203cf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "50ad0c8fdf57f7ff2925f97c94f4bff705fcd1ebbb4a95f664d4c2d17f51930d"

  strings:
    $s1  = "function ScriptEngineMinorVersion() {" fullword ascii
    $s2  = "function anmatyfq5() {" fullword ascii
    $s3  = "function hbarzan9() {" fullword ascii
    $s4  = "function voqfu9() {" fullword ascii
    $s5  = "return mfuvyg2;" fullword ascii
    $s6  = "function lqogmir9() {" fullword ascii
    $s7  = "return vuhxa7;" fullword ascii
    $s8  = "function icetcenbus2() {" fullword ascii
    $s9  = "return mvibvugaver5;" fullword ascii
    $s10 = "return anuttogcysxo2;" fullword ascii
    $s11 = "function cnesgewsikse0() {" fullword ascii
    $s12 = "return ysotywo2;" fullword ascii
    $s13 = "function atux7() {" fullword ascii
    $s14 = "function jemy7() {" fullword ascii
    $s15 = "return bahyzh7;" fullword ascii
    $s16 = "return iscobhiqjuvd7;" fullword ascii
    $s17 = "return ejsustyxo0;" fullword ascii
    $s18 = "function evijbyjuwz0() {" fullword ascii
    $s19 = "return wdedmimt0;" fullword ascii
    $s20 = "function smyvurw7() {" fullword ascii

  condition:
    uint16(0) == 0x7274 and
    8 of them
}