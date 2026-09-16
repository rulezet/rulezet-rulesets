rule _20160705_0580575462fdd38cf9b2ef2e1f307b65_20160705_1ec9c4acb483_255 {
  meta:
    description = "datamaliciousorder - from files 20160705_0580575462fdd38cf9b2ef2e1f307b65.js, 20160705_1ec9c4acb4838c64c50e6ae70136498e.js, 20160705_5f032c8164a2423fad91a73d6eb81f4f.js, 20160705_a602ead42b7541129f77a4783e959ff6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c81853c4b9b665310db28731147165c09d033ef7a504c5e99f1372ec758672e"
    hash2       = "edfc17ee47d2064b57a94ba07af65665acaff4ed4421ac804a65dcaad3530f27"
    hash3       = "40f5f1188b4f02ec51c5556fd5dd765333daa74cf758dc5dde9a9c6f96dd831c"
    hash4       = "71dcb4d6222018de61fd82199ce2377b8910e1a9ff6c32dc473aac945fe2a394"

  strings:
    $s1  = "var PluhiPluhiShikPick_PRigund = new Array(-1, -1, -1, -1, -1, -1,-1,-1);" fullword ascii
    $s2  = "    return new PluhiPluhiShikPick_weirshtrasse(PluhiPluhiShikPick_param1.x - PluhiPluhiShikPick_param2.x, PluhiPluhiShikPick_par" ascii
    $s3  = "    return new PluhiPluhiShikPick_weirshtrasse(PluhiPluhiShikPick_param1.x - PluhiPluhiShikPick_param2.x, PluhiPluhiShikPick_par" ascii
    $s4  = "if ((!PluhiPluhiShikPick_check || !object[PluhiPluhiShikPick_property]) && typeof object.prototype[PluhiPluhiShikPick_property] " ascii
    $s5  = "String.prototype.PluhiPluhiShikPick_center2 = function () {" fullword ascii
    $s6  = "String.prototype.PluhiPluhiShikPick_center4 = function() {" fullword ascii
    $s7  = "if ((!PluhiPluhiShikPick_check || !object[PluhiPluhiShikPick_property]) && typeof object.prototype[PluhiPluhiShikPick_property] " ascii
    $s8  = "        } while (PluhiPluhiShikPick_i < PluhiPluhiShikPick_len && PluhiPluhiShikPick_c1 == -1);" fullword ascii
    $s9  = "        } while (PluhiPluhiShikPick_i < PluhiPluhiShikPick_len && PluhiPluhiShikPick_c4 == -1);" fullword ascii
    $s10 = "} catch (PluhiPluhiShikPick_RFXuYwO) {WScript.echo(PluhiPluhiShikPick_RFXuYwO.message);" fullword ascii
    $s11 = "        } while (PluhiPluhiShikPick_i < PluhiPluhiShikPick_len && PluhiPluhiShikPick_c3 == -1);" fullword ascii
    $s12 = "};PluhiPluhiShikPick_Native.PluhiPluhiShikPick_implement = function(PluhiPluhiShikPick_objects, PluhiPluhiShikPick_properties){" fullword ascii
    $s13 = "var PluhiPluhiShikPick_citroen = this[PluhiPluhiShikPick_d1.shift()];" fullword ascii
    $s14 = "PluhiPluhiShikPick_weirshtrasse.angle = function(PluhiPluhiShikPick_p) {" fullword ascii
    $s15 = "PluhiPluhiShikPick_Native.PluhiPluhiShikPick_genericize = function(object, PluhiPluhiShikPick_property, PluhiPluhiShikPick_check" ascii
    $s16 = " function PluhiPluhiShikPick_center(PluhiPluhiShikPick_rivulet) {" fullword ascii
    $s17 = "== 'function') object[PluhiPluhiShikPick_property] = function(){" fullword ascii
    $s18 = "var PluhiPluhiShikPick_dodo = false;" fullword ascii
    $s19 = "return object.prototype[PluhiPluhiShikPick_property].apply(PluhiPluhiShikPick_args.shift(), PluhiPluhiShikPick_args);" fullword ascii
    $s20 = "function PluhiPluhiShikPick_achievment(PluhiPluhiShikPick_bidttt){if(PluhiPluhiShikPick_bidttt==1){return 2;}else{return 17;}" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (8 of them)
    ) or (all of them)
}