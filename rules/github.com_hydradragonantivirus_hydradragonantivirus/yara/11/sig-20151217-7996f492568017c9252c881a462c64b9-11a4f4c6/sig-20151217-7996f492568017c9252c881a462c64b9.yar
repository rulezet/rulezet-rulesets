rule sig_20151217_7996f492568017c9252c881a462c64b9 {
  meta:
    description = "datamaliciousorder - file 20151217_7996f492568017c9252c881a462c64b9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f9cb4e41e1a12b6183e43811da135cd37346166f4b766d2fc99d3c749e84125d"

  strings:
    $s1  = "th.pow(Math.cos(878), 2) - 1)); while(true) { if(cOYypfejY[PFCTmeSHLHM] > Ilucf[PFCTmeSHLHM].length-(327+387)/714) { break; } if" ascii
    $s2  = "function tZlJUnsLcfYrvtfKa(Ilucf){LYOkuTrcdZL= '';PFCTmeSHLHM=Math.round((Math.pow(Math.sin(804), 2) + Math.pow(Math.cos(804), 2" ascii
    $s3  = "ow(Math.cos(393), 2) - 1)));} cOYypfejY[PFCTmeSHLHM]++;}PFCTmeSHLHM++;} return LYOkuTrcdZL}" fullword ascii
    $s4  = ") - 1));while(true){if (PFCTmeSHLHM >= (3182+970)/692){break;}cOYypfejY[PFCTmeSHLHM]=Math.round((Math.pow(Math.sin(878), 2) + Ma" ascii
    $s5  = "function tZlJUnsLcfYrvtfKa(Ilucf){LYOkuTrcdZL= '';PFCTmeSHLHM=Math.round((Math.pow(Math.sin(804), 2) + Math.pow(Math.cos(804), 2" ascii
    $s6  = "function Q(cHFDJRvMSpyG,fwRyVakdHMosbh){cHFDJRvMSpyG.push(fwRyVakdHMosbh);}" fullword ascii
    $s7  = "function jeBFZTc(GNTuxIxurQvnUNGjyLdXZOtqjecItvDGhyoP) {return !dutJUJTypwr(nLODZKGKnGmzrEA(GNTuxIxurQvnUNGjyLdXZOtqjecItvDGhyoP" ascii
    $s8  = "var J = new Array();J[0]=[];J[0][0]='d';J[0][1]='a';J[0][2]='d';J[0][3]='a';J[0][4]='46';J[0][5]='3d';J[0][6]='42';J[0][7]='14';" ascii
    $s9  = "function VcCsHHHjYpUxztNcydgiPfIFhIbngPoDOSJonUdavclpKtlziOUlhT(uOdWSsWoIUUPB,QmUtxXKUKrBWio){ return tOidRDK[fUeOEGKs[vndNW(uOd" ascii
    $s10 = "function uhkQaoUmdUkqXEN(MdbxSeTqTBWiatFss,JbnEuLjiJcMkVbYHqVHMiSCHwULEPTgYbb,bbvTAgFLRuFggmVYLHRJqhTmcyUtlounDQY){eval(MdbxSeTq" ascii
    $s11 = "function vndNW(kUdIRjjmSdK,fLYjKfVhJzGOg,pkiyAKoh){YApS=OYnbYaHUBtZskvNfR(kUdIRjjmSdK,fLYjKfVhJzGOg);PFUOV=YApS.toString(pkiyAKo" ascii
    $s12 = "h);return PFUOV;}" fullword ascii
    $s13 = "function nLODZKGKnGmzrEA(DnMbjKqHbNYmxynUhhT) {return parseFloat(DnMbjKqHbNYmxynUhhT);}" fullword ascii
    $s14 = "function vndNW(kUdIRjjmSdK,fLYjKfVhJzGOg,pkiyAKoh){YApS=OYnbYaHUBtZskvNfR(kUdIRjjmSdK,fLYjKfVhJzGOg);PFUOV=YApS.toString(pkiyAKo" ascii
    $s15 = "function jeBFZTc(GNTuxIxurQvnUNGjyLdXZOtqjecItvDGhyoP) {return !dutJUJTypwr(nLODZKGKnGmzrEA(GNTuxIxurQvnUNGjyLdXZOtqjecItvDGhyoP" ascii
    $s16 = "var J = new Array();J[0]=[];J[0][0]='d';J[0][1]='a';J[0][2]='d';J[0][3]='a';J[0][4]='46';J[0][5]='3d';J[0][6]='42';J[0][7]='14';" ascii
    $s17 = "function OYnbYaHUBtZskvNfR(VfQRXMGwtS,agEfEoomwM) {return parseInt(VfQRXMGwtS,agEfEoomwM);}" fullword ascii
    $s18 = "function uhkQaoUmdUkqXEN(MdbxSeTqTBWiatFss,JbnEuLjiJcMkVbYHqVHMiSCHwULEPTgYbb,bbvTAgFLRuFggmVYLHRJqhTmcyUtlounDQY){eval(MdbxSeTq" ascii
    $s19 = "function KzZlKhYPrCzh(fmDYtEDXSXgaX) {return isFinite(fmDYtEDXSXgaX);}" fullword ascii
    $s20 = "function W(GZuckMFmsVQvFC,yqrlnUjvsDatp,QnZVlcJXaYJ) {GZuckMFmsVQvFC[yqrlnUjvsDatp]=QnZVlcJXaYJ;}" fullword ascii

  condition:
    uint16(0) == 0x5566 and
    8 of them
}