rule sig_20160530_fd7f4f66524f50dc78aa00879ba2f706 {
  meta:
    description = "datamaliciousorder - file 20160530_fd7f4f66524f50dc78aa00879ba2f706.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1ccb5aaebe1639fd2de1754ed76419e812f6900927b29b1750e6381e39283d85"

  strings:
    $s1  = "var uDQaaT=function(){return WScript.CreateObject(OipTZR[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function oMwXXoQ(VzSMvsRaBcWE,QqNimGbtE){return VzSMvsRaBcWE.charAt(QqNimGbtE);}" fullword ascii
    $s3  = "pTZR[5],true);" fullword ascii
    $s4  = "function doqcLaL(){return kCtLlnHCRcB(OipTZR[11],[2,4,8,10],OipTZR[12]);}" fullword ascii
    $s5  = "var YAMnPqJhGpXAmy=function(){return new ActiveXObject(OipTZR[1]);}();" fullword ascii
    $s6  = "var xSrqMYRaStwp = YAMnPqJhGpXAmy.createtextfile(uDQaaT.ExpandEnvironmentStrings(OipTZR[3]+OipTZR[4])+String.fromCharCode(92)+Oi" ascii
    $s7  = "function iwkLhnIBWZUsHoFhxTnxZSZR(llwdDPYrxDxuPsMTEnXWi,SuvQTPJMiT,wbTTECnHJIil){return String.fromCharCode(llwdDPYrxDxuPsMTEnXW" ascii
    $s8  = "function kCtLlnHCRcB(CkiEcfJyazj,egAMjWaNtq,tmrNMwOHj){FHrWYGJpCptk=CkiEcfJyazj.split(tmrNMwOHj);QiShjGoxxxlLY = OipTZR[0];for(o" ascii
    $s9  = "length);return xCuSAqGsVnEKfPE;}" fullword ascii
    $s10 = "function eODDheeDxrv(qvhWqAiyjjvxm) {var dawrNBwWEtKdK = aWQfTFEC.join(OipTZR[7]);var RgHIAreEppE, QviCO, KcZiQRMChmKFIYRXzzxn, " ascii
    $s11 = "function ctPXLpWvTX(doDwZlyCXrkfxRSKVmQqEH,KjqUXaTKImKqsfyroH){return String.fromCharCode(doDwZlyCXrkfxRSKVmQqEH,KjqUXaTKImKqsfy" ascii
    $s12 = "function iwkLhnIBWZUsHoFhxTnxZSZR(llwdDPYrxDxuPsMTEnXWi,SuvQTPJMiT,wbTTECnHJIil){return String.fromCharCode(llwdDPYrxDxuPsMTEnXW" ascii
    $s13 = "xCuSAqGsVnEKfPE += nk(RgHIAreEppE);else if (ntyadAcTDNLMpvVVk == 64) xCuSAqGsVnEKfPE += ctPXLpWvTX(RgHIAreEppE, QviCO);else xCuS" ascii
    $s14 = "AqGsVnEKfPE += iwkLhnIBWZUsHoFhxTnxZSZR(RgHIAreEppE, QviCO, KcZiQRMChmKFIYRXzzxn);} while (nbNEfEZiKQvcJwRwWMbz < qvhWqAiyjjvxm." ascii
    $s15 = "function dCDRXqxUNsWToJVJBse(vRQizCyJNed,wwJLDhdgVDlS){return vRQizCyJNed.indexOf(wwJLDhdgVDlS);}" fullword ascii
    $s16 = "function MLRuXuCOqYonfR(){return kCtLlnHCRcB(OipTZR[13],[0,3,6],OipTZR[14]);}" fullword ascii
    $s17 = "function eODDheeDxrv(qvhWqAiyjjvxm) {var dawrNBwWEtKdK = aWQfTFEC.join(OipTZR[7]);var RgHIAreEppE, QviCO, KcZiQRMChmKFIYRXzzxn, " ascii
    $s18 = "function EOXWy(tSELpwHrxubl,jobFc) {var ksZBMwMZv=[OipTZR[15]];tSELpwHrxubl[ksZBMwMZv[0]]" fullword ascii
    $s19 = "function ctPXLpWvTX(doDwZlyCXrkfxRSKVmQqEH,KjqUXaTKImKqsfyroH){return String.fromCharCode(doDwZlyCXrkfxRSKVmQqEH,KjqUXaTKImKqsfy" ascii
    $s20 = "function kCtLlnHCRcB(CkiEcfJyazj,egAMjWaNtq,tmrNMwOHj){FHrWYGJpCptk=CkiEcfJyazj.split(tmrNMwOHj);QiShjGoxxxlLY = OipTZR[0];for(o" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}