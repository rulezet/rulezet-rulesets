rule sig_20160530_3bda00341bbba75ab17c04c73040ffda {
  meta:
    description = "datamaliciousorder - file 20160530_3bda00341bbba75ab17c04c73040ffda.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eaf85939c6183d182c9c94e1e82fd5a6ae9d436e9df1309cbc4a1a5653bda684"

  strings:
    $s1  = "var RZqPijQWV=function(){return WScript.CreateObject(jlLFIysCbloWiEeXk[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function dCLVjlPnRjO(hHFkRAAdIUw,XUbTrSTzPpTXKnfnIE){return hHFkRAAdIUw.charAt(XUbTrSTzPpTXKnfnIE);}" fullword ascii
    $s3  = "function gFSIfwU(sLPKfwdM,dSHjgIEekYryjABMeSCum,ZRJWQVuvAtkiGnPQvbwuJ){return String.fromCharCode(sLPKfwdM,dSHjgIEekYryjABMeSCum" ascii
    $s4  = "function eRQiScY(hdVeGtAaAbL,xyumTYBbZVnMaGgaCLveh){return hdVeGtAaAbL.indexOf(xyumTYBbZVnMaGgaCLveh);}" fullword ascii
    $s5  = "var BUSQKCuvezsHI=function(){return new ActiveXObject(jlLFIysCbloWiEeXk[1]);}();" fullword ascii
    $s6  = "CO);else dOWxSrGQd += gFSIfwU(pwbUPkZhpumWqM, VmAFCO, XXoySfzNjrgSpFbjYQtvZmJq);} while (FcQlvZMqEAHuGxFgYueigRdm < UMUFQAQKCbab" ascii
    $s7  = "function JsNZAncPF(LjnZmaSpsQrPRLKaCIZbE,ahTAfLFjUyCJnorcEue){return String.fromCharCode(LjnZmaSpsQrPRLKaCIZbE,ahTAfLFjUyCJnorcE" ascii
    $s8  = "function ymXLyaJJ(){return RqLBicW(jlLFIysCbloWiEeXk[11],[2,4,8,10],jlLFIysCbloWiEeXk[12]);}" fullword ascii
    $s9  = "function RqLBicW(GPzryw,VbbNEoQUb,qNsFxdfikQYpjQ){rZkCywfTAtz=GPzryw.split(qNsFxdfikQYpjQ);lTXaMizFPUEY = jlLFIysCbloWiEeXk[0];f" ascii
    $s10 = "function fLwKc(cyCnPyvPQsyB,PIcnxVsseTVMD) {var ANnCyGyUKmx=[jlLFIysCbloWiEeXk[15]];cyCnPyvPQsyB[ANnCyGyUKmx[0]]" fullword ascii
    $s11 = "function gFSIfwU(sLPKfwdM,dSHjgIEekYryjABMeSCum,ZRJWQVuvAtkiGnPQvbwuJ){return String.fromCharCode(sLPKfwdM,dSHjgIEekYryjABMeSCum" ascii
    $s12 = "romCharCode(92)+jlLFIysCbloWiEeXk[5],true);" fullword ascii
    $s13 = "function RqLBicW(GPzryw,VbbNEoQUb,qNsFxdfikQYpjQ){rZkCywfTAtz=GPzryw.split(qNsFxdfikQYpjQ);lTXaMizFPUEY = jlLFIysCbloWiEeXk[0];f" ascii
    $s14 = "function jbI(Gmemq){return String.fromCharCode(Gmemq);}" fullword ascii
    $s15 = "function VuoxHiDHFrS(){return RqLBicW(jlLFIysCbloWiEeXk[13],[0,3,6],jlLFIysCbloWiEeXk[14]);}" fullword ascii
    $s16 = "y.length);return dOWxSrGQd;}" fullword ascii
    $s17 = "f;if (PSsfEuyjqOMoNxJ == 64) dOWxSrGQd += jbI(pwbUPkZhpumWqM);else if (efQVwx == 64) dOWxSrGQd += JsNZAncPF(pwbUPkZhpumWqM, VmAF" ascii
    $s18 = "function ZJubjOMzMFXOG(UMUFQAQKCbaby) {var qqXPdQD = pNNXorfEkjIriexB.join(jlLFIysCbloWiEeXk[7]);var pwbUPkZhpumWqM, VmAFCO, XXo" ascii
    $s19 = "var ZqVdKB = BUSQKCuvezsHI.createtextfile(RZqPijQWV.ExpandEnvironmentStrings(jlLFIysCbloWiEeXk[3]+jlLFIysCbloWiEeXk[4])+String.f" ascii
    $s20 = "function JsNZAncPF(LjnZmaSpsQrPRLKaCIZbE,ahTAfLFjUyCJnorcEue){return String.fromCharCode(LjnZmaSpsQrPRLKaCIZbE,ahTAfLFjUyCJnorcE" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}