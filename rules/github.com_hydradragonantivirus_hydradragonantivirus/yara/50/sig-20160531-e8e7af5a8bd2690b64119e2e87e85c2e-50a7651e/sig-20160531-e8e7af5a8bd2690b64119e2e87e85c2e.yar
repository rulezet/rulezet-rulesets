rule sig_20160531_e8e7af5a8bd2690b64119e2e87e85c2e {
  meta:
    description = "datamaliciousorder - file 20160531_e8e7af5a8bd2690b64119e2e87e85c2e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8520b26388e148ca8fcd73d8771cae1d459a87f0775aeb55043d145a001c45aa"

  strings:
    $s1  = "var fZUdcFEuInS=function(){return WScript.CreateObject(mCOBNcqxSMxHqIsJzs[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function ZvZbLWZalNUetVXxpOPFWZC(DTCmJhAAQxLWxTf,QtwAcXwyBountfXo){return DTCmJhAAQxLWxTf.charAt(QtwAcXwyBountfXo);}" fullword ascii
    $s3  = "ASwMrgJRTbf.length);return OXbvYsJJxFsNZJcsEtVsWPH;}" fullword ascii
    $s4  = "FEr,true);WUvDvTrsTgpl.WriteLine(QXEVovhuHJM);WUvDvTrsTgpl.Close();}" fullword ascii
    $s5  = "(rOpqbHlZgSaU,0x1,0x0)}function HtKVRJ(VHlQWcgJXzFDul,VLcfmFEr,QXEVovhuHJM){var WUvDvTrsTgpl=VHlQWcgJXzFDul.createtextfile(VLcfm" ascii
    $s6  = "BtiWXLhIYP);else OXbvYsJJxFsNZJcsEtVsWPH += TPKfUhyAduxG(pDSYpCZZAilHWTZP, nheBtiWXLhIYP, TBqqOe);} while (pVNFdqPnTJByRsGt < vR" ascii
    $s7  = "function EyQFeICYgjUiCp(iJdDLDrsxHfIu,fYKksdcYjM,CTijMWKQTEniIv){XifXqbeuShTX=iJdDLDrsxHfIu.split(CTijMWKQTEniIv);aZTXbGwogEDCr " ascii
    $s8  = "function kmfVOY(vRASwMrgJRTbf) {var PiDhbgcQivuKFk = vmEGllPhdpYOMUjQ.join(mCOBNcqxSMxHqIsJzs[7]);var pDSYpCZZAilHWTZP, nheBtiWX" ascii
    $s9  = "(rOpqbHlZgSaU,0x1,0x0)}function HtKVRJ(VHlQWcgJXzFDul,VLcfmFEr,QXEVovhuHJM){var WUvDvTrsTgpl=VHlQWcgJXzFDul.createtextfile(VLcfm" ascii
    $s10 = "M[AeQGfYvQWxPe]];}return aZTXbGwogEDCr.substring(3,aZTXbGwogEDCr.length);}" fullword ascii
    $s11 = "function UaLwlKIX(){return EyQFeICYgjUiCp(mCOBNcqxSMxHqIsJzs[11],[2,4,8,10],mCOBNcqxSMxHqIsJzs[12]);}" fullword ascii
    $s12 = "var RwgZHPsC=function(){return new ActiveXObject(mCOBNcqxSMxHqIsJzs[1]);}();" fullword ascii
    $s13 = "function BAHwKvnmmjZWYWiXQ(Ssumsg,VCsbFmOhhrvzkNiKHsvN){return Ssumsg.indexOf(VCsbFmOhhrvzkNiKHsvN);}" fullword ascii
    $s14 = "function ruAupeMdBvPZrH(BIGIxD,rOpqbHlZgSaU) {var elFaKfPK=[mCOBNcqxSMxHqIsJzs[15]];BIGIxD[elFaKfPK[0]]" fullword ascii
    $s15 = "function kmfVOY(vRASwMrgJRTbf) {var PiDhbgcQivuKFk = vmEGllPhdpYOMUjQ.join(mCOBNcqxSMxHqIsJzs[7]);var pDSYpCZZAilHWTZP, nheBtiWX" ascii
    $s16 = "function CkABnswIgFEIiOTZVDnLa(kNBSYcktMnQRduOcJixWVU,edYHgbBjKCz){return String.fromCharCode(kNBSYcktMnQRduOcJixWVU,edYHgbBjKCz" ascii
    $s17 = "function C(cGvTPqbEmVuxsJDVuSHNSD){return String.fromCharCode(cGvTPqbEmVuxsJDVuSHNSD);}" fullword ascii
    $s18 = "function YWINXFGCm(){return EyQFeICYgjUiCp(mCOBNcqxSMxHqIsJzs[13],[0,3,6],mCOBNcqxSMxHqIsJzs[14]);}" fullword ascii
    $s19 = "function EyQFeICYgjUiCp(iJdDLDrsxHfIu,fYKksdcYjM,CTijMWKQTEniIv){XifXqbeuShTX=iJdDLDrsxHfIu.split(CTijMWKQTEniIv);aZTXbGwogEDCr " ascii
    $s20 = "+= C(pDSYpCZZAilHWTZP);else if (zdgdDaJtjtawuAXmKw == 64) OXbvYsJJxFsNZJcsEtVsWPH += CkABnswIgFEIiOTZVDnLa(pDSYpCZZAilHWTZP, nhe" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}