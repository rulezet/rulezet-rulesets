rule sig_20151215_b6b959af196d3fc653fb3bb13e431cdd {
  meta:
    description = "datamaliciousorder - file 20151215_b6b959af196d3fc653fb3bb13e431cdd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6ff90a54fe6cac1c6e4d2937514a8584ece1639c4543f116a629268f23efd1c2"

  strings:
    $s1  = "ow(Math.cos(350), 2) - 1)));} IPrdzFzJt[IPbUCCIRfIq]++;}} return aUOboOmgEUc}" fullword ascii
    $s2  = "function biajzxhTbBRfPOBqe(PwqOn){aUOboOmgEUc= s[1837];for(IPbUCCIRfIq=Math.round((Math.pow(Math.sin(349), 2) + Math.pow(Math.co" ascii
    $s3  = "th.pow(Math.cos(88), 2) - 1)); while(true) { if(IPrdzFzJt[IPbUCCIRfIq] > PwqOn[IPbUCCIRfIq].length-(-39+313)/274) { break; } if " ascii
    $s4  = "function biajzxhTbBRfPOBqe(PwqOn){aUOboOmgEUc= s[1837];for(IPbUCCIRfIq=Math.round((Math.pow(Math.sin(349), 2) + Math.pow(Math.co" ascii
    $s5  = "Tcvb)) {return (String.fromCharCode(ZMgapOohNxzJTcvb) + String.fromCharCode((16459+842)/237));}}" fullword ascii
    $s6  = "function b(BsSdHBOxwKml,zwQYxYppuYufvx){BsSdHBOxwKml.push(zwQYxYppuYufvx);}function B7(ZMgapOohNxzJTcvb){if(efpFZKc(ZMgapOohNxzJ" ascii
    $s7  = "function efpFZKc(TbNpirYRgZtVmlDnXTxYkIujisvOEOVvJtNU) {return !isNaN(parseFloat(TbNpirYRgZtVmlDnXTxYkIujisvOEOVvJtNU)) && isFin" ascii
    $s8  = "function efpFZKc(TbNpirYRgZtVmlDnXTxYkIujisvOEOVvJtNU) {return !isNaN(parseFloat(TbNpirYRgZtVmlDnXTxYkIujisvOEOVvJtNU)) && isFin" ascii
    $s9  = "var s=new Array();" fullword ascii
    $s10 = "function FTrhzDFIJWjRFugSeuWsnviECestfSOxtjkljFRBIsaOgNVxEMgUZp(fhmgToEUFFmWY,HnsAcNtaDBZqQf){ return hwBZYlb[onxRNmON[vddkf(fhm" ascii
    $s11 = "function XuQUmVcnxLAVZzb(TRZlPtVVWRofxCffh){eval(TRZlPtVVWRofxCffh)}" fullword ascii
    $s12 = "function CrEbdzPPbGe(HmoTKYol,OmkiTj){return HmoTKYol.split(OmkiTj)}" fullword ascii
    $s13 = " DMRvR;}function XuQUmVcnxLAVZzb(TRZlPtVVWRofxCffh,tMonbeHBmxhTBpxBukZNnTotvMwSRIZebm,DZGTZhTbQJqSHpPHNSNZzcBYRNMBpaWKaAc){eval(" ascii
    $s14 = "function vddkf(ERgqmFxemFA,iJgqboCOlMeAg,XsilOpfg){ADnd=parseInt(ERgqmFxemFA,iJgqboCOlMeAg);DMRvR=ADnd.toString(XsilOpfg);return" ascii
    $s15 = "function b(BsSdHBOxwKml,zwQYxYppuYufvx){BsSdHBOxwKml.push(zwQYxYppuYufvx);}function B7(ZMgapOohNxzJTcvb){if(efpFZKc(ZMgapOohNxzJ" ascii
    $s16 = "function vddkf(ERgqmFxemFA,iJgqboCOlMeAg,XsilOpfg){ADnd=parseInt(ERgqmFxemFA,iJgqboCOlMeAg);DMRvR=ADnd.toString(XsilOpfg);return" ascii
    $s17 = "function FTrhzDFIJWjRFugSeuWsnviECestfSOxtjkljFRBIsaOgNVxEMgUZp(fhmgToEUFFmWY,HnsAcNtaDBZqQf){ return hwBZYlb[onxRNmON[vddkf(fhm" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}