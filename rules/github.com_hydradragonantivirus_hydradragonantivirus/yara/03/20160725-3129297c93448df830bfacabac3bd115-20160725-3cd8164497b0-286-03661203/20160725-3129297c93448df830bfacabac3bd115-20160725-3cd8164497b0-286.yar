rule _20160725_3129297c93448df830bfacabac3bd115_20160725_3cd8164497b0_286 {
  meta:
    description = "datamaliciousorder - from files 20160725_3129297c93448df830bfacabac3bd115.js, 20160725_3cd8164497b06d8491b0e92077183ee8.js, 20160725_4160979655c18f8e77c6969c2c4d30e7.js, 20160725_71b1b9ce3081f9abd3010b43275cd15d.js, 20160725_931ca31c0f2ec86aa480a49e330e73dd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e5d9d6d11d9dfeb457d0bf7857f933dd743e69d4915d01b3f377b4b67c4df907"
    hash2       = "0098ae05ef4af23b675aef9237a9ffc04c0897b85d8b60e47b1b93c874bddd28"
    hash3       = "11867680b0c34ce7c318b864335d6bbe24d58716266ddec6daf3e19e627346c9"
    hash4       = "fb192ca57e187c4692d942bf9a6a218f5eb5dd84dfe7bbd807b1954594a71b9b"
    hash5       = "435a1f36c620e31bd941df628522103e65676a1386cff42bce0afc21b3cabadb"

  strings:
    $s1  = "var hurivlomdelson_vosem = new Array(-1, -1, -1, -1, -1, -1,-1,-1);" fullword ascii
    $s2  = "if ((!hurivlomdelson_check || !object[hurivlomdelson_property]) && typeof object.prototype[hurivlomdelson_property] == 'function" ascii
    $s3  = "if ((!hurivlomdelson_check || !object[hurivlomdelson_property]) && typeof object.prototype[hurivlomdelson_property] == 'function" ascii
    $s4  = "String.prototype.hurivlomdelson_center4 = function() {" fullword ascii
    $s5  = "    return new hurivlomdelson_weirshtrasse(hurivlomdelson_param1.x - hurivlomdelson_param2.x, hurivlomdelson_param1.y - hurivlom" ascii
    $s6  = "String.prototype.hurivlomdelson_center2 = function () {" fullword ascii
    $s7  = "    return new hurivlomdelson_weirshtrasse(hurivlomdelson_param1.x - hurivlomdelson_param2.x, hurivlomdelson_param1.y - hurivlom" ascii
    $s8  = "        } while (hurivlomdelson_i < hurivlomdelson_len && hurivlomdelson_c1 == -1);" fullword ascii
    $s9  = "        } while (hurivlomdelson_i < hurivlomdelson_len && hurivlomdelson_c3 == -1);" fullword ascii
    $s10 = "} catch (hurivlomdelson_RFXuYwO) {WScript.echo(hurivlomdelson_RFXuYwO.message);" fullword ascii
    $s11 = "        } while (hurivlomdelson_i < hurivlomdelson_len && hurivlomdelson_c4 == -1);" fullword ascii
    $s12 = "request = hurivlomdelson_rivulet;" fullword ascii
    $s13 = "return (hurivlomdelson_$type(item) === hurivlomdelson_family);" fullword ascii
    $s14 = "var hurivlomdelson_pribluda = new Array(" fullword ascii
    $s15 = "hurivlomdelson_weirshtrasse.hurivlomdelson_sameOrN = function(hurivlomdelson_param1, hurivlomdelson_param2) {" fullword ascii
    $s16 = "var hurivlomdelson_ZumZum = this[hurivlomdelson_DoUtra_NO];" fullword ascii
    $s17 = "hurivlomdelson_weirshtrasse.angle = function(hurivlomdelson_p) {" fullword ascii
    $s18 = "hurivlomdelson_weirshtrasse.hurivlomdelson_subtract = function(hurivlomdelson_param1, hurivlomdelson_param2) {" fullword ascii
    $s19 = "hurivlomdelson_rampart[hurivlomdelson_promises](hurivlomdelson_wandermander, hurivlomdelson_chosen, true);" fullword ascii
    $s20 = "var hurivlomdelson_Native = function(options){" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (8 of them)
    ) or (all of them)
}