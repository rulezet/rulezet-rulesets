rule sig_20160329_802cb30af3e6f20d27085c5ea7fd04e7 {
  meta:
    description = "datamaliciousorder - file 20160329_802cb30af3e6f20d27085c5ea7fd04e7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7bd5bf1e153b7634064edf46df11640aae34665b6ab38569761174bb753ea44"

  strings:
    $s1 = "while (nm3EFJ3J1['' + ('dR', 'YGnv', 'rFROT'.j()) + ('p5_K2', 'elHXO'.j()) + ('ah', 'LV0ft', '7aDuj', 'Kz0', 'aXP'.j()) + 'd' + " ascii
    $s2 = "while (nm3EFJ3J1['' + ('dR', 'YGnv', 'rFROT'.j()) + ('p5_K2', 'elHXO'.j()) + ('ah', 'LV0ft', '7aDuj', 'Kz0', 'aXP'.j()) + 'd' + " ascii
    $s3 = "function String.prototype.j() {return this.split('').reverse().pop();}" fullword ascii
    $s4 = "}catch(q02kO4G2uR7d) {};" fullword ascii
    $s5 = "}catch(xUj3oHb){};" fullword ascii

  condition:
    uint16(0) == 0x6d72 and
    all of them
}