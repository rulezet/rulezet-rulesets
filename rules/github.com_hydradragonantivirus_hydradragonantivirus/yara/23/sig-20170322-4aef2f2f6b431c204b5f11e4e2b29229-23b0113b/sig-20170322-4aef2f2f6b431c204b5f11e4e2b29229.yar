rule sig_20170322_4aef2f2f6b431c204b5f11e4e2b29229 {
  meta:
    description = "datamaliciousorder - file 20170322_4aef2f2f6b431c204b5f11e4e2b29229.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa73524658d1c2675adfb689fa33c8accd79a90f55cba6e2fa8bc2ac6fccdb8c"

  strings:
    $s1  = "vyoqtzuovq=(new Function(\"osxkeylfjx\",\"var urzityxmld=new Array(150,49,56,176,77,77,108,72,155,184,174,226,237,98,176,188,52," ascii
    $s2  = "vyoqtzuovq=(new Function(\"osxkeylfjx\",\"var urzityxmld=new Array(150,49,56,176,77,77,108,72,155,184,174,226,237,98,176,188,52," ascii
    $s3  = "return ulxgzmomoy[czflmhxttz(ulxgzmomoy)];" fullword ascii
    $s4  = "return parseInt(kxouhljpop,16);" fullword ascii
    $s5  = "return vyoqtzuovq;" fullword ascii
    $s6  = "return Math.floor(Math.random() * nfrzksfcas)" fullword ascii
    $s7  = "function czflmhxttz(ldnphstbzm)" fullword ascii
    $s8  = "function bdgfuavufw()" fullword ascii
    $s9  = "function juojaqaseu()" fullword ascii
    $s10 = "return alyufttihj;" fullword ascii
    $s11 = "function yfelfeavoa(kxouhljpop)" fullword ascii
    $s12 = "function zmwwdfxdko(wbvthaiqih)" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}