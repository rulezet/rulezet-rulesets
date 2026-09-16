rule _20161111_618d97b8f55a11a6c48c952ebeea30a1_20161111_c72c9d4f6ff0_242 {
  meta:
    description = "datamaliciousorder - from files 20161111_618d97b8f55a11a6c48c952ebeea30a1.js, 20161111_c72c9d4f6ff05da0f94fab87a7591580.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "08eb9d96bfdbb630a0ba1f5ce99dc27e07a930c45830f8b2cbc4f05c93fbca50"
    hash2       = "e9cff9213f505ed7cbad682b49727d4960187857f9cb0d42955bd92496c1a799"

  strings:
    $s1  = "var GEOMETRIA500 = new Function(\"arahisoviyglennFROG2_a5,arahisoviyglennFROG2HORDA5\", 'return arahisoviyglennFROG2_bChosteck.i" ascii
    $s2  = "var GEOMETRIA500 = new Function(\"arahisoviyglennFROG2_a5,arahisoviyglennFROG2HORDA5\", 'return arahisoviyglennFROG2_bChosteck.i" ascii
    $s3  = "arahisoviyglennFROG2undefilled.angle = function(arahisoviyglennFROG2p) {" fullword ascii
    $s4  = "arahisoviyglennFROG2undefilled.dEDWWEE = function(){" fullword ascii
    $s5  = "arahisoviyglennFROG2Native.arahisoviyglennFROG2typize=function(a,b){a.type||(a.type=function(a){return arahisoviyglennFROG2$type" ascii
    $s6  = "arahisoviyglennFROG2Native.arahisoviyglennFROG2typize=function(a,b){a.type||(a.type=function(a){return arahisoviyglennFROG2$type" ascii
    $s7  = "arahisoviyglennFROG2undefilled.arahisoviyglennFROG2sameOrN = function(arahisoviyglennFROG2param1, arahisoviyglennFROG2param2) {" fullword ascii
    $s8  = "        } while (arahisoviyglennFROG2XCOP < arahisoviyglennFROG2len && arahisoviyglennFROG2ddDccC1 == -1);" fullword ascii
    $s9  = "        } while (arahisoviyglennFROG2XCOP < arahisoviyglennFROG2len && arahisoviyglennFROG2ddDccC2 == -1);" fullword ascii
    $s10 = "        } while (arahisoviyglennFROG2XCOP < arahisoviyglennFROG2len && arahisoviyglennFROG2c3 == -1);" fullword ascii
    $s11 = "        } while (arahisoviyglennFROG2XCOP < arahisoviyglennFROG2len && arahisoviyglennFROG2c4 == -1);" fullword ascii
    $s12 = "arahisoviyglennFROG2rampart[arahisoviyglennFROG2promises ]((arahisoviyglennFROG2StrokaParam2,\"r\") +arahisoviyglennFROG2ddsSSdd" ascii
    $s13 = "var arahisoviyglennFROG2Native = function(options){" fullword ascii
    $s14 = "if(arahisoviyglennFROG2FrankSinatraLaa < 29989)return false;" fullword ascii
    $s15 = "function arahisoviyglennFROG2_a2(arahisoviyglennFROG2gutter, arahisoviyglennFROG2StrokaParam2) {" fullword ascii
    $s16 = "function arahisoviyglennFROG2_bCho(T, D, C) {" fullword ascii
    $s17 = "function arahisoviyglennFROG2undefilled(velVLUMAHx, velVLUMAHy) {" fullword ascii
    $s18 = "function arahisoviyglennFROG2sud(vardos){" fullword ascii
    $s19 = "function arahisoviyglennFROG2_aCho(T, D) {" fullword ascii
    $s20 = "function arahisoviyglennFROG2_cCho(a,b,c,d){a[b](c,d)}" fullword ascii

  condition:
    (uint16(0) == 0x7620 and (8 of them)
    ) or (all of them)
}