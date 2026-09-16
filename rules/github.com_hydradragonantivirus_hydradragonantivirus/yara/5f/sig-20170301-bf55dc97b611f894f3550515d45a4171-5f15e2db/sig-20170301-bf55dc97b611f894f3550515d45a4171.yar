rule sig_20170301_bf55dc97b611f894f3550515d45a4171 {
  meta:
    description = "datamaliciousorder - file 20170301_bf55dc97b611f894f3550515d45a4171.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8cd65b5c63c43395f00bebeedcf122d0d95ecec7fb5361740d07bbebb61fa7ed"

  strings:
    $s1 = "var x = new Array(\"jeannetaylordds.com\", \"iveybusiness.vmnow.co\", \"ted-woodworking-plans.com\", \"ronniespersonaltouchjanit" ascii
    $s2 = "var x = new Array(\"jeannetaylordds.com\", \"iveybusiness.vmnow.co\", \"ted-woodworking-plans.com\", \"ronniespersonaltouchjanit" ascii
    $s3 = "e[raspbna2s[9-9+0]](\"G\"+\"ET\", t4 + \":\"+ter+ter+x[i]+\"/c\"+\"o\"+\"u\"+\"n\"+\"ter/?\"+m,false);" fullword ascii
    $s4 = "return new ActiveXObject(g2);" fullword ascii
    $s5 = "var vDJmB = function(){" fullword ascii
    $s6 = "function mesuto() {" fullword ascii
    $s7 = "function reqty(fdga) { eval(fdga); }" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}