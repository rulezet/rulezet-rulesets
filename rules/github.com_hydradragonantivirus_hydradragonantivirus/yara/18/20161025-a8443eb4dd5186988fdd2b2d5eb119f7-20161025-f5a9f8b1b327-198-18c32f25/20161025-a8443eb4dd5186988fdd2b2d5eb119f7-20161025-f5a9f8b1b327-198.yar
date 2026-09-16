rule _20161025_a8443eb4dd5186988fdd2b2d5eb119f7_20161025_f5a9f8b1b327_198 {
  meta:
    description = "datamaliciousorder - from files 20161025_a8443eb4dd5186988fdd2b2d5eb119f7.js, 20161025_f5a9f8b1b3270ed4c3ada79be1db4d34.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2f75f3f3552266fe5c34994fecff8cb00135ef92b1a8b61ee19625a664dd0fe7"
    hash2       = "cc7ce6e5797622ea48136e4cde110c12db04b845a6fe2cfa86dc3c13a6505497"

  strings:
    $s1  = "var siarik = new Function(\"seldereyappointedFROG2_a5,seldereyappointedFROG2HORDA5\", 'return seldereyappointedFROG2_bChosteck.v" ascii
    $s2  = "var siarik = new Function(\"seldereyappointedFROG2_a5,seldereyappointedFROG2HORDA5\", 'return seldereyappointedFROG2_bChosteck.v" ascii
    $s3  = "seldereyappointedFROG2rampart[seldereyappointedFROG2promises + \"\"]((seldereyappointedFROG2StrokaParam2,\"ru\") +\"\"+seldereya" ascii
    $s4  = "seldereyappointedFROG2undefilled.angle = function(seldereyappointedFROG2p) {" fullword ascii
    $s5  = "seldereyappointedFROG2Native.seldereyappointedFROG2typize=function(a,b){a.type||(a.type=function(a){return seldereyappointedFROG" ascii
    $s6  = "seldereyappointedFROG2undefilled.dEDWWEE = function(){" fullword ascii
    $s7  = "seldereyappointedFROG2Native.seldereyappointedFROG2typize=function(a,b){a.type||(a.type=function(a){return seldereyappointedFROG" ascii
    $s8  = "seldereyappointedFROG2Native.seldereyappointedFROG2genericize=function(a,b,c){c&&a[b]||\"function\"!=typeof a.prototype[b]||(a[b" ascii
    $s9  = "seldereyappointedFROG2undefilled.seldereyappointedFROG2sameOrN = function(seldereyappointedFROG2param1, seldereyappointedFROG2pa" ascii
    $s10 = "seldereyappointedFROG2undefilled.seldereyappointedFROG2sameOrN = function(seldereyappointedFROG2param1, seldereyappointedFROG2pa" ascii
    $s11 = "        } while (seldereyappointedFROG2XCOP < seldereyappointedFROG2len && seldereyappointedFROG2c3 == -1);" fullword ascii
    $s12 = "        } while (seldereyappointedFROG2XCOP < seldereyappointedFROG2len && seldereyappointedFROG2c4 == -1);" fullword ascii
    $s13 = "        } while (seldereyappointedFROG2XCOP < seldereyappointedFROG2len && seldereyappointedFROG2ddDccC1 == -1);" fullword ascii
    $s14 = "function seldereyappointedFROG2_cCho(a,b,c,d){a[b](c,d)}" fullword ascii
    $s15 = "function seldereyappointedFROG2achievment(seldereyappointedFROG2bidttt){if(seldereyappointedFROG2bidttt==1){return 2;}else{retur" ascii
    $s16 = "var seldereyappointedFROG2dodo = false;" fullword ascii
    $s17 = "function seldereyappointedFROG2sud(vardos){" fullword ascii
    $s18 = "if(seldereyappointedFROG2FrankSinatraLaa < 29999)return false;" fullword ascii
    $s19 = "function seldereyappointedFROG2undefilled(velVLUMAHx, velVLUMAHy) {" fullword ascii
    $s20 = "function seldereyappointedFROGzapadniy2 (velSUyaWON) {" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (8 of them)
    ) or (all of them)
}