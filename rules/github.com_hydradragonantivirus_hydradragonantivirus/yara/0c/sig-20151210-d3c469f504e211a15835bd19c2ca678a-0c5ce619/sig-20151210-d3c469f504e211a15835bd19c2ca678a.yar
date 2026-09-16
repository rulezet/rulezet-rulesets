rule sig_20151210_d3c469f504e211a15835bd19c2ca678a {
  meta:
    description = "datamaliciousorder - file 20151210_d3c469f504e211a15835bd19c2ca678a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f07d75fd2f06c1ee67159eff4cca9824165b7560cac3aa697e99d92baf809dfd"

  strings:
    $s1  = "function jwbcp(AMKdRqJfOhG,hPuWvuBHLTFuy,XbZYNmVr){cQyc=parseInt(AMKdRqJfOhG,hPuWvuBHLTFuy);WjdgL=cQyc.toString(XbZYNmVr);return" ascii
    $s2  = "function gogfqXi(ahFBYVvYmVQpAbYYZQldmsAjyBRpNgjwZPRM) {return !isNaN(parseFloat(ahFBYVvYmVQpAbYYZQldmsAjyBRpNgjwZPRM)) && isFin" ascii
    $s3  = " WjdgL;}function PWndBWiVChRomPf(PmIKavlZvNKbQEaGO){eval(PmIKavlZvNKbQEaGO)}" fullword ascii
    $s4  = "function gogfqXi(ahFBYVvYmVQpAbYYZQldmsAjyBRpNgjwZPRM) {return !isNaN(parseFloat(ahFBYVvYmVQpAbYYZQldmsAjyBRpNgjwZPRM)) && isFin" ascii
    $s5  = "function jwbcp(AMKdRqJfOhG,hPuWvuBHLTFuy,XbZYNmVr){cQyc=parseInt(AMKdRqJfOhG,hPuWvuBHLTFuy);WjdgL=cQyc.toString(XbZYNmVr);return" ascii
    $s6  = "function PxrvloBgxjECpYQqP(IiJUn){MXxekCdHyNI= '';for(MJUFsQRceeR=(-619+619)/152; MJUFsQRceeR < (721+937)/829; MJUFsQRceeR++) {w" ascii
    $s7  = "function YnLtrzHTmkf(hEcihuBV,PwNrqL){return hEcihuBV.split(PwNrqL)}" fullword ascii
    $s8  = "VVOygXD=(-702+702)/24;while(true){if(VVOygXD>=(61453+243)/482){break;}bhfoEDzLaSPTi[VVOygXD]=String.fromCharCode(VVOygXD);VVOygX" ascii
    $s9  = ";}} return MXxekCdHyNI}" fullword ascii
    $s10 = "function PxrvloBgxjECpYQqP(IiJUn){MXxekCdHyNI= '';for(MJUFsQRceeR=(-619+619)/152; MJUFsQRceeR < (721+937)/829; MJUFsQRceeR++) {w" ascii
    $s11 = "function vQfZGYcjxoLmFQtowtlYQTjpyRtXovXViTVsBFmoXIEFAIyyUdKoUA(YbpTQjgcqsPiT,ufVfBssTJdqRBQ){ return bhfoEDzLaSPTi[jwbcp(YbpTQj" ascii
    $s12 = "VVOygXD=(-702+702)/24;while(true){if(VVOygXD>=(61453+243)/482){break;}bhfoEDzLaSPTi[VVOygXD]=String.fromCharCode(VVOygXD);VVOygX" ascii
    $s13 = "function vQfZGYcjxoLmFQtowtlYQTjpyRtXovXViTVsBFmoXIEFAIyyUdKoUA(YbpTQjgcqsPiT,ufVfBssTJdqRBQ){ return bhfoEDzLaSPTi[jwbcp(YbpTQj" ascii
    $s14 = "pprjaqgq[MJUFsQRceeR]=(-239+239)/996; while(true) { if(wpprjaqgq[MJUFsQRceeR] > IiJUn[MJUFsQRceeR].length-(314+162)/476) { break" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}