rule sig_20160525_ce4d54f4f3ef231ebb13afd95d2cc364 {
  meta:
    description = "datamaliciousorder - file 20160525_ce4d54f4f3ef231ebb13afd95d2cc364.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "73b255c078538ed83ee382deb8e40bf4dc46b3717971c34911c084ad46999c78"

  strings:
    $s1  = "ath.round((Math.pow(Math.sin(475), 2) + Math.pow(Math.cos(475), 2) - 1))-858)) QJDQsiXzqKeNbfjjHA += iR(yTSdTVkjEFWRf);else if (" ascii
    $s2  = "round((Math.pow(Math.sin(372), 2) + Math.pow(Math.cos(372), 2) - 1))-246) | QVigbreibqXeVxnuJzM<< (665 + Math.round((Math.pow(Ma" ascii
    $s3  = "function LsyuI(CjhyesEOaSTMg) {var EebRFgx = yLDIFSaBDRLYeyoTMuHQRcMD.join(GBhqz[0]);var yTSdTVkjEFWRf, ioDtx, WCiBXP, DlXFbYuR," ascii
    $s4  = "function bjyBEGPqtbKPnyQzEgPS(PoHRVctiujeoHy,wdGpkNSzZbAlsDh){return PoHRVctiujeoHy.charAt(wdGpkNSzZbAlsDh);}" fullword ascii
    $s5  = "function LsyuI(CjhyesEOaSTMg) {var EebRFgx = yLDIFSaBDRLYeyoTMuHQRcMD.join(GBhqz[0]);var yTSdTVkjEFWRf, ioDtx, WCiBXP, DlXFbYuR," ascii
    $s6  = "aPzfpsNjfYzCTYcU < CjhyesEOaSTMg.length);return QJDQsiXzqKeNbfjjHA;}" fullword ascii
    $s7  = "function bznsqoxtPDNjrBnyIQUQ(hQTNZBnFCqKvrTbXbQe,hQfgOnUoHqcFnJGEjGfJWPIY){return hQTNZBnFCqKvrTbXbQe.indexOf(hQfgOnUoHqcFnJGEj" ascii
    $s8  = "PDNjrBnyIQUQ(EebRFgx,bjyBEGPqtbKPnyQzEgPS(CjhyesEOaSTMg,hWcaskPaPzfpsNjfYzCTYcU++));GNuzMVXqGrSUxdHrQy = DlXFbYuR<< (264 + Math." ascii
    $s9  = "function iR(pqDRbSjOzgTRUsZlOZrSzM){return String.fromCharCode(pqDRbSjOzgTRUsZlOZrSzM);}" fullword ascii
    $s10 = "function bznsqoxtPDNjrBnyIQUQ(hQTNZBnFCqKvrTbXbQe,hQfgOnUoHqcFnJGEjGfJWPIY){return hQTNZBnFCqKvrTbXbQe.indexOf(hQfgOnUoHqcFnJGEj" ascii
    $s11 = "function UXJNGHPzgRMuzsSAPcG(FMnAOy,CrZjkxuXjrUUgaabVWt){return String.fromCharCode(FMnAOy,CrZjkxuXjrUUgaabVWt);}" fullword ascii
    $s12 = "function OjMSV(ZjPQLKcMAGNalQ,BMjIkSc,VABldi){return String.fromCharCode(ZjPQLKcMAGNalQ,BMjIkSc,VABldi);}" fullword ascii
    $s13 = "jHA += UXJNGHPzgRMuzsSAPcG(yTSdTVkjEFWRf, ioDtx);else QJDQsiXzqKeNbfjjHA += OjMSV(yTSdTVkjEFWRf, ioDtx, WCiBXP);} while (hWcaskP" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}