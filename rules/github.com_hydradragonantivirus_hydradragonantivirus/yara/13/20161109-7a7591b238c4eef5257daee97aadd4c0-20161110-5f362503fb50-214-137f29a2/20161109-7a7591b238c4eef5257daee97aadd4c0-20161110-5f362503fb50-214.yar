rule _20161109_7a7591b238c4eef5257daee97aadd4c0_20161110_5f362503fb50_214 {
  meta:
    description = "datamaliciousorder - from files 20161109_7a7591b238c4eef5257daee97aadd4c0.js, 20161110_5f362503fb50b200ac97c7689865e93a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ad67e6dad0fcf720d78837654ba1d7370ea847cdda9d05a9c18bdc2d744583f"
    hash2       = "8e5868cc43092ab4048e1c68dd7020a9f7cbff82eaa9957fe695df60d8eb7bcc"

  strings:
    $s1  = "var DEVCKAGDEB500 = new Function(\"kukurukufigurativeFROG2_a5,kukurukufigurativeFROG2HORDA5\", 'return kukurukufigurativeFROG2_b" ascii
    $s2  = "kukurukufigurativeFROG2Native.kukurukufigurativeFROG2typize=function(a,b){a.type||(a.type=function(a){return kukurukufigurativeF" ascii
    $s3  = "kukurukufigurativeFROG2undefilled.kukurukufigurativeFROG2sameOrN = function(kukurukufigurativeFROG2param1, kukurukufigurativeFRO" ascii
    $s4  = "kukurukufigurativeFROG2undefilled.dEDWWEE = function(){" fullword ascii
    $s5  = "kukurukufigurativeFROG2undefilled.angle = function(kukurukufigurativeFROG2p) {" fullword ascii
    $s6  = "kukurukufigurativeFROG2Native.kukurukufigurativeFROG2typize=function(a,b){a.type||(a.type=function(a){return kukurukufigurativeF" ascii
    $s7  = "kukurukufigurativeFROG2undefilled.kukurukufigurativeFROG2sameOrN = function(kukurukufigurativeFROG2param1, kukurukufigurativeFRO" ascii
    $s8  = "        } while (kukurukufigurativeFROG2XCOP < kukurukufigurativeFROG2len && kukurukufigurativeFROG2c4 == -1);" fullword ascii
    $s9  = "        } while (kukurukufigurativeFROG2XCOP < kukurukufigurativeFROG2len && kukurukufigurativeFROG2ddDccC1 == -1);" fullword ascii
    $s10 = "        } while (kukurukufigurativeFROG2XCOP < kukurukufigurativeFROG2len && kukurukufigurativeFROG2c3 == -1);" fullword ascii
    $s11 = "function kukurukufigurativeFROG2undefilled(velVLUMAHx, velVLUMAHy) {" fullword ascii
    $s12 = "};kukurukufigurativeFROG2Native.kukurukufigurativeFROG2XCOPmplement = function(kukurukufigurativeFROG2objects, kukurukufigurativ" ascii
    $s13 = "if (kukurukufigurativeFROG2FrankSinatra[0]!= 77 || kukurukufigurativeFROG2FrankSinatra[1]!= 90)return false;" fullword ascii
    $s14 = "function kukurukufigurativeFROG2_a2(kukurukufigurativeFROG2gutter, kukurukufigurativeFROG2StrokaParam2) {" fullword ascii
    $s15 = "function kukurukufigurativeFROG_OOO_OOO(TT){" fullword ascii
    $s16 = "function kukurukufigurativeFROG2_aCho(T, D) {" fullword ascii
    $s17 = "function kukurukufigurativeFROG2_bCho(T, D, C) {" fullword ascii
    $s18 = "if(kukurukufigurativeFROG2FrankSinatraLaa < 29989)return false;" fullword ascii
    $s19 = "var kukurukufigurativeFROG2dodo = false;" fullword ascii
    $s20 = "var DEVCKAGDEB500 = new Function(\"kukurukufigurativeFROG2_a5,kukurukufigurativeFROG2HORDA5\", 'return kukurukufigurativeFROG2_b" ascii

  condition:
    (uint16(0) == 0x0a0d and (8 of them)
    ) or (all of them)
}