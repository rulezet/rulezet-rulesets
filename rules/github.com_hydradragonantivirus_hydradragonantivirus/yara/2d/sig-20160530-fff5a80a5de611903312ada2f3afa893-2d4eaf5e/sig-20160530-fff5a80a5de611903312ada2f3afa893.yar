rule sig_20160530_fff5a80a5de611903312ada2f3afa893 {
  meta:
    description = "datamaliciousorder - file 20160530_fff5a80a5de611903312ada2f3afa893.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "17e54f3af9f312bd0a478c483f104bfa5615af8f83725364c0b045b4dc3c078e"

  strings:
    $s1  = "var nJeaXEewlZV=function(){return WScript.CreateObject(NWCjFkWtIUAm[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function YcSKOBTivA(dKcKESOCIw,OJRmgSFdxpMyueGTWdofQhV){return dKcKESOCIw.charAt(OJRmgSFdxpMyueGTWdofQhV);}" fullword ascii
    $s3  = "function vHszGGqJIUha(toyhCVuouIGqaqesQyBZP,BsxRXNFeAK,mhMxcYoITFZ){return String.fromCharCode(toyhCVuouIGqaqesQyBZP,BsxRXNFeAK," ascii
    $s4  = "function YvLZnYYEfGyjDk(oeXxCbp,ilrHAFePzM,MNdVWQtjid){bqHYxPHZ=oeXxCbp.split(MNdVWQtjid);kckAOwhOBs = NWCjFkWtIUAm[0];for(ICgKg" ascii
    $s5  = "de(92)+NWCjFkWtIUAm[5],true);" fullword ascii
    $s6  = "function vHszGGqJIUha(toyhCVuouIGqaqesQyBZP,BsxRXNFeAK,mhMxcYoITFZ){return String.fromCharCode(toyhCVuouIGqaqesQyBZP,BsxRXNFeAK," ascii
    $s7  = "function PJjbvVFbVvJH(){return YvLZnYYEfGyjDk(NWCjFkWtIUAm[13],[0,3,6],NWCjFkWtIUAm[14]);}" fullword ascii
    $s8  = "gfEhJ < AsugXqkXoUQXO.length);return KyTXYJoMbut;}" fullword ascii
    $s9  = "var AAiXzlN = EdTdzlwAMYR.createtextfile(nJeaXEewlZV.ExpandEnvironmentStrings(NWCjFkWtIUAm[3]+NWCjFkWtIUAm[4])+String.fromCharCo" ascii
    $s10 = "function XTunfMuoLVLDJ(){return nJeaXEewlZV.ExpandEnvironmentStrings(qlBXYdxuZYZOf())}" fullword ascii
    $s11 = "var EdTdzlwAMYR=function(){return new ActiveXObject(NWCjFkWtIUAm[1]);}();" fullword ascii
    $s12 = "function onNLbDSgDXiClulJWD(pwRqXblkNroITwMpcoUq,mJgTklsORNmtYryFMZdxHeQ){return pwRqXblkNroITwMpcoUq.indexOf(mJgTklsORNmtYryFMZ" ascii
    $s13 = "function Penxglveq(AsugXqkXoUQXO) {var QHduRjnp = IIHmjmWkUtEBdRzBxy.join(NWCjFkWtIUAm[7]);var AxsjZDsrfcVBYMOErpsXIvE, AqTbJlSk" ascii
    $s14 = "function tsACKFQKMdcO(lbDcdUIwEcIhWkKDnuROdhl,XzkdfROuVcLUGrMgxFNHyt){return String.fromCharCode(lbDcdUIwEcIhWkKDnuROdhl,XzkdfRO" ascii
    $s15 = "push(\"D\");IIHmjmWkUtEBdRzBxy.push(\"3\");IIHmjmWkUtEBdRzBxy.push(\"E\");IIHmjmWkUtEBdRzBxy.push(\"F\");IIHmjmWkUtEBdRzBxy.push" ascii
    $s16 = "function YAVceWOxJCXXx(CmaiVIaVVa,TyRGIFS) {var HUtpqkscD=[NWCjFkWtIUAm[15]];CmaiVIaVVa[HUtpqkscD[0]]" fullword ascii
    $s17 = "= oq(AxsjZDsrfcVBYMOErpsXIvE);else if (eYTZhNQuFW == 64) KyTXYJoMbut += tsACKFQKMdcO(AxsjZDsrfcVBYMOErpsXIvE, AqTbJlSkjdSPbHXOxT" ascii
    $s18 = "P=0;ICgKgP<ilrHAFePzM.length;ICgKgP++) {kckAOwhOBs+=bqHYxPHZ[ilrHAFePzM[ICgKgP]];}return kckAOwhOBs.substring(3,kckAOwhOBs.lengt" ascii
    $s19 = "function TANOcba(){return YvLZnYYEfGyjDk(NWCjFkWtIUAm[11],[2,4,8,10],NWCjFkWtIUAm[12]);}" fullword ascii
    $s20 = "function oq(DrUfqiJUuYlEtjwtJ){return String.fromCharCode(DrUfqiJUuYlEtjwtJ);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}