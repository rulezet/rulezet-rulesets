rule sig_20151211_44c009609d8b8e03f531e7feb8484ee9 {
  meta:
    description = "datamaliciousorder - file 20151211_44c009609d8b8e03f531e7feb8484ee9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1ddb9c2084263702428bc42bdbe7fea1dfdf2e425d11876df51144af2b204b69"

  strings:
    $s1  = "function sRlEyoO(SRxVHDVYxKehSJCPJBwOHzIFbgwOAQTRvNwN) {return !isNaN(parseFloat(SRxVHDVYxKehSJCPJBwOHzIFbgwOAQTRvNwN)) && isFin" ascii
    $s2  = "function sRlEyoO(SRxVHDVYxKehSJCPJBwOHzIFbgwOAQTRvNwN) {return !isNaN(parseFloat(SRxVHDVYxKehSJCPJBwOHzIFbgwOAQTRvNwN)) && isFin" ascii
    $s3  = "var e=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"3i\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s4  = "function lhXxmlaGXkxlQypvIITXZFYZRIWohgMkydLqEFtVTZZwqqgdBllXJq(pdevJcCFWFtBV,sxfTKlGzVuJTCg){ return EcCce[GieCb(pdevJcCFWFtBV[" ascii
    $s5  = "var ei=new Array(\"2a\",\"2d\",\"29\",\"2e\",\"2d\",\"26\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\"," ascii
    $s6  = "wiLqXoql[IMuFsaXhSdG]=(-808+808)/444; while(true) { if(NwiLqXoql[IMuFsaXhSdG] > dXlSo[IMuFsaXhSdG].length-(-179+273)/94) { break" ascii
    $s7  = "function GieCb(ZKBRZrVsIRM,zEquwNkikvWwV,pZxrpopy){CvFO=parseInt(ZKBRZrVsIRM,zEquwNkikvWwV);fdNOD=CvFO.toString(pZxrpopy);return" ascii
    $s8  = " fdNOD;}function JKXCNhqQCtAzBOw(EPERUpjIfmZMHOkFD){eval(EPERUpjIfmZMHOkFD)}" fullword ascii
    $s9  = "function lhXxmlaGXkxlQypvIITXZFYZRIWohgMkydLqEFtVTZZwqqgdBllXJq(pdevJcCFWFtBV,sxfTKlGzVuJTCg){ return EcCce[GieCb(pdevJcCFWFtBV[" ascii
    $s10 = "var ei=new Array(\"2a\",\"2d\",\"29\",\"2e\",\"2d\",\"26\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\"," ascii
    $s11 = "var e=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"3i\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s12 = "+;}IMuFsaXhSdG++;} return CTgskzQfAHe}" fullword ascii
    $s13 = "function GieCb(ZKBRZrVsIRM,zEquwNkikvWwV,pZxrpopy){CvFO=parseInt(ZKBRZrVsIRM,zEquwNkikvWwV);fdNOD=CvFO.toString(pZxrpopy);return" ascii
    $s14 = "function SQCJksRxCnY(iDzdABjR,WcMwCj){return iDzdABjR.split(WcMwCj)}" fullword ascii
    $s15 = "function HgUQMBoJnVcafjjnp(dXlSo){CTgskzQfAHe= '';IMuFsaXhSdG=(-130+130)/868; while(true){if(IMuFsaXhSdG >= (872+30)/451)break;N" ascii
    $s16 = "function HgUQMBoJnVcafjjnp(dXlSo){CTgskzQfAHe= '';IMuFsaXhSdG=(-130+130)/868; while(true){if(IMuFsaXhSdG >= (872+30)/451)break;N" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}