rule sig_20160526_9303e3c6ea9c69f12a67f2913db80bd1 {
  meta:
    description = "datamaliciousorder - file 20160526_9303e3c6ea9c69f12a67f2913db80bd1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "567293db5e7c841b847dfa5a9134abc9226f22b35cd529e1c406727462ef524d"

  strings:
    $s1  = "n(705), 2) + Math.pow(Math.cos(705), 2) - 1))-262)) zSVDggH += TUxJOLfGsqfL(bElut, DKAPZtXD);else zSVDggH += XeBqDFmEoqJeSAr(bEl" ascii
    $s2  = ", 2) + Math.pow(Math.cos(209), 2) - 1))-951)) zSVDggH += BC(bElut);else if (LcvfHlRTeHUmw == (326 + Math.round((Math.pow(Math.si" ascii
    $s3  = "function yrkmBFdQZLb(pmYVBgVavVAIn) {var ywdxaNJDeEffRPNpoueU = kxOdeeeoJiHQvHKR.join(UWUzBHHfjjuhyNpJNkrl[0]);var bElut, DKAPZt" ascii
    $s4  = "function NDpKFbnirUzMwJSWgL(EBEbbfSfB,VPGxYvlPQQ){return EBEbbfSfB.charAt(VPGxYvlPQQ);}" fullword ascii
    $s5  = "function XeBqDFmEoqJeSAr(TXKerehIngcjJD,HiujIqUobKAyVqRjbu,TdrvOgcFeW){return String.fromCharCode(TXKerehIngcjJD,HiujIqUobKAyVqR" ascii
    $s6  = "function TUxJOLfGsqfL(ZXZECFqLlbt,TQCfyfNCjBbdNRkeSSvOIId){return String.fromCharCode(ZXZECFqLlbt,TQCfyfNCjBbdNRkeSSvOIId);}" fullword ascii
    $s7  = "function yrkmBFdQZLb(pmYVBgVavVAIn) {var ywdxaNJDeEffRPNpoueU = kxOdeeeoJiHQvHKR.join(UWUzBHHfjjuhyNpJNkrl[0]);var bElut, DKAPZt" ascii
    $s8  = "VAIn,uQWgiXVBNQtnRVcpih++));dVHjEpA = vqcSiBzibZMkjNPVWDGCwhe(ywdxaNJDeEffRPNpoueU,NDpKFbnirUzMwJSWgL(pmYVBgVavVAIn,uQWgiXVBNQtn" ascii
    $s9  = "function BC(BYfrIXU){return String.fromCharCode(BYfrIXU);}" fullword ascii
    $s10 = "function XeBqDFmEoqJeSAr(TXKerehIngcjJD,HiujIqUobKAyVqRjbu,TdrvOgcFeW){return String.fromCharCode(TXKerehIngcjJD,HiujIqUobKAyVqR" ascii
    $s11 = "ut, DKAPZtXD, LdIdvxkoMUUCzHqKFNFWrYZp);} while (uQWgiXVBNQtnRVcpih < pmYVBgVavVAIn.length);return zSVDggH;}" fullword ascii
    $s12 = "function vqcSiBzibZMkjNPVWDGCwhe(aOMQpDx,bYuqDNqfE){return aOMQpDx.indexOf(bYuqDNqfE);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}