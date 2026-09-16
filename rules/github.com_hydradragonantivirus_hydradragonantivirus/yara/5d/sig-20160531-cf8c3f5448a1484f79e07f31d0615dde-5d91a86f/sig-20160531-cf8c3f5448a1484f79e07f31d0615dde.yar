rule sig_20160531_cf8c3f5448a1484f79e07f31d0615dde {
  meta:
    description = "datamaliciousorder - file 20160531_cf8c3f5448a1484f79e07f31d0615dde.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "436b3ce84dca1d506b0350a0d0c00a8076ce7d09b5460e3ee084e5e905de96ae"

  strings:
    $s1  = "var kIdQnXQjM=function(){return WScript.CreateObject(hUDCvzVPpHjypZEJnxehn[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function dXUaEYmTzaL(dZQhKOetakqB,voQxIbhiFeYEs,aRSfkmKo){TTlsq=dZQhKOetakqB.split(aRSfkmKo);wJWYf = hUDCvzVPpHjypZEJnxehn[0];fo" ascii
    $s3  = "r(JzfNmj=0;JzfNmj<voQxIbhiFeYEs.length;JzfNmj++) {wJWYf+=TTlsq[voQxIbhiFeYEs[JzfNmj]];}return wJWYf.substring(3,wJWYf.length);}" fullword ascii
    $s4  = "function dXUaEYmTzaL(dZQhKOetakqB,voQxIbhiFeYEs,aRSfkmKo){TTlsq=dZQhKOetakqB.split(aRSfkmKo);wJWYf = hUDCvzVPpHjypZEJnxehn[0];fo" ascii
    $s5  = "function HJwzGThVy(VNhAYqENySZ,MbqhzrXfxWBpOEOTMKS){return VNhAYqENySZ.charAt(MbqhzrXfxWBpOEOTMKS);}" fullword ascii
    $s6  = "(rMNFXfqAKoRZ,0x1,0x0)}function nXzzpfWFUhAg(gSHOCdDfCk,xKeyhdPE,LouVAGQ){var KmoaQSTlhFHwr=gSHOCdDfCk.createtextfile(xKeyhdPE,t" ascii
    $s7  = "(rMNFXfqAKoRZ,0x1,0x0)}function nXzzpfWFUhAg(gSHOCdDfCk,xKeyhdPE,LouVAGQ){var KmoaQSTlhFHwr=gSHOCdDfCk.createtextfile(xKeyhdPE,t" ascii
    $s8  = ".length);return pAiSdXpEbEwdTzGh;}" fullword ascii
    $s9  = "function JvKdDJaBOOMEk(){return dXUaEYmTzaL(hUDCvzVPpHjypZEJnxehn[13],[0,3,6],hUDCvzVPpHjypZEJnxehn[14]);}" fullword ascii
    $s10 = "function nAqtTphiIsDlw(ItuwNPEjBIfYgNdSNPr,MRYEyOGSXhidUsXb,IzIDFlAYVLEGwGTPlgloXclA){return String.fromCharCode(ItuwNPEjBIfYgNd" ascii
    $s11 = "function exUwPDyrpIAXLB(){return dXUaEYmTzaL(hUDCvzVPpHjypZEJnxehn[11],[2,4,8,10],hUDCvzVPpHjypZEJnxehn[12]);}" fullword ascii
    $s12 = "function dcetyiCCcgXAOvbeWnzi(jolZxFfiLln,NWvjukIyhbmYJAUNxrzRNvU){return String.fromCharCode(jolZxFfiLln,NWvjukIyhbmYJAUNxrzRNv" ascii
    $s13 = "function usvqcgHmrEdBm(PzKhlTmgPDEQR) {var xwAINSidqhNkixGPwSwADng = FGUnMzusp.join(hUDCvzVPpHjypZEJnxehn[7]);var gTDldoRDUMNrvi" ascii
    $s14 = "function dcetyiCCcgXAOvbeWnzi(jolZxFfiLln,NWvjukIyhbmYJAUNxrzRNvU){return String.fromCharCode(jolZxFfiLln,NWvjukIyhbmYJAUNxrzRNv" ascii
    $s15 = "function byNWQFjIOQnSHDyATpSk(ykKtZgbhWTlHroeZksk,HSNHExvbvjPAcuGXwB){return ykKtZgbhWTlHroeZksk.indexOf(HSNHExvbvjPAcuGXwB);}" fullword ascii
    $s16 = " pAiSdXpEbEwdTzGh += nAqtTphiIsDlw(gTDldoRDUMNrviwZynrdkJS, zmPjgraYELSWibX, UtbYWLrAKd);} while (aketDadJbCFFeo < PzKhlTmgPDEQR" ascii
    $s17 = "function Jc(rDKtrlEThMsaAtFFDle){return String.fromCharCode(rDKtrlEThMsaAtFFDle);}" fullword ascii
    $s18 = "function KZWOwXZQpOCMYv(){return dXUaEYmTzaL(hUDCvzVPpHjypZEJnxehn[9],[1,5,7],hUDCvzVPpHjypZEJnxehn[10]);}" fullword ascii
    $s19 = "function nAqtTphiIsDlw(ItuwNPEjBIfYgNdSNPr,MRYEyOGSXhidUsXb,IzIDFlAYVLEGwGTPlgloXclA){return String.fromCharCode(ItuwNPEjBIfYgNd" ascii
    $s20 = "function eGrqBogUVIty(KsvHmnjUuuZmQ,rMNFXfqAKoRZ) {var PVwLdX=[hUDCvzVPpHjypZEJnxehn[15]];KsvHmnjUuuZmQ[PVwLdX[0]]" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}