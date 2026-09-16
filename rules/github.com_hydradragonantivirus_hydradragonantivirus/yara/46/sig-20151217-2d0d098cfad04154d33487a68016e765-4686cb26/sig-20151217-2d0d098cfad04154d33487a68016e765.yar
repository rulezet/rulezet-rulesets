rule sig_20151217_2d0d098cfad04154d33487a68016e765 {
  meta:
    description = "datamaliciousorder - file 20151217_2d0d098cfad04154d33487a68016e765.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49e4e137f724751e1a939426b43ea7c93deb91e7a9988fcaf5a68bb23463f9a2"

  strings:
    $s1  = "h.pow(Math.cos(114), 2) - 1)); while(true) { if(WjXTawFMN[rnegFbXVCTp] > LedMK[rnegFbXVCTp].length-(232+591)/823) { break; } if " ascii
    $s2  = "function HAdwkTPfWmzFGXCQo(LedMK){aaKEeaYiFPQ= '';rnegFbXVCTp=Math.round((Math.pow(Math.sin(721), 2) + Math.pow(Math.cos(721), 2" ascii
    $s3  = ") - 1));while(true){if (rnegFbXVCTp >= (588+900)/248){break;}WjXTawFMN[rnegFbXVCTp]=Math.round((Math.pow(Math.sin(114), 2) + Mat" ascii
    $s4  = "ow(Math.cos(830), 2) - 1)));} WjXTawFMN[rnegFbXVCTp]++;}rnegFbXVCTp++;} return aaKEeaYiFPQ}" fullword ascii
    $s5  = "function HAdwkTPfWmzFGXCQo(LedMK){aaKEeaYiFPQ= '';rnegFbXVCTp=Math.round((Math.pow(Math.sin(721), 2) + Math.pow(Math.cos(721), 2" ascii
    $s6  = "function wJLHoTT(LQttFKpXfImhrNoVfdfhXNxnfdqLrsHAUXlV) {return !VsHIBlKkRIC(DWvaGyYqQtrDBNj(LQttFKpXfImhrNoVfdfhXNxnfdqLrsHAUXlV" ascii
    $s7  = "a);return rMxTw;}" fullword ascii
    $s8  = "function KsgdbqMEVbqOHObftcgTZvTPMthAyjuEyAceyOZNsPHPmThBIRHnnE(hEGjUCbHajYZE,RNduOzplAQktIk){ return fxDYGiH[soyrbzvQ[pbWOn(hEG" ascii
    $s9  = "function gbyMyqmSnflxHbt(lsghKhRtPQfjHdFHn,EnWcixvcthEuWazNUQaWTCTKbsoZXfhJAV,hGhXdRbZoZGuGfPnZlMRzxubXUVivONBABl){eval(lsghKhRt" ascii
    $s10 = "function A(NEKWDpfPhYRW,GkrLMpboRenQac){NEKWDpfPhYRW.push(GkrLMpboRenQac);}" fullword ascii
    $s11 = "function gbyMyqmSnflxHbt(lsghKhRtPQfjHdFHn,EnWcixvcthEuWazNUQaWTCTKbsoZXfhJAV,hGhXdRbZoZGuGfPnZlMRzxubXUVivONBABl){eval(lsghKhRt" ascii
    $s12 = ",'(',',','n','V','+','W','R','$','$','@','s','X','7','2',']','Y','y','Y','<','D','Z','k',';','D','[','V','`','&','[','E',String." ascii
    $s13 = "function KsgdbqMEVbqOHObftcgTZvTPMthAyjuEyAceyOZNsPHPmThBIRHnnE(hEGjUCbHajYZE,RNduOzplAQktIk){ return fxDYGiH[soyrbzvQ[pbWOn(hEG" ascii
    $s14 = "var y = new Array();y[0]=[];y[0][0]='d';y[0][1]='a';y[0][2]='d';y[0][3]='a';y[0][4]='46';y[0][5]='3d';y[0][6]='42';y[0][7]='14';" ascii
    $s15 = "function VsHIBlKkRIC(hPBZYtLSitQZwx) {return isNaN(hPBZYtLSitQZwx);}" fullword ascii
    $s16 = "function wJLHoTT(LQttFKpXfImhrNoVfdfhXNxnfdqLrsHAUXlV) {return !VsHIBlKkRIC(DWvaGyYqQtrDBNj(LQttFKpXfImhrNoVfdfhXNxnfdqLrsHAUXlV" ascii
    $s17 = "function DWvaGyYqQtrDBNj(AmdDCWUwbVdtnfOWaqI) {return parseFloat(AmdDCWUwbVdtnfOWaqI);}" fullword ascii
    $s18 = "function G(RguIBNJxUzZGLO,WzouaHuAZRNVV,vBQOrXiofHb) {RguIBNJxUzZGLO[WzouaHuAZRNVV]=vBQOrXiofHb;}" fullword ascii
    $s19 = "function AwRiIBQSbAwW(VmfwssVymNYxP) {return isFinite(VmfwssVymNYxP);}" fullword ascii
    $s20 = "function pbWOn(jSPFfzMmrFu,kHNQhlmEncOIy,nHYAAXva){oHdH=lgtadCpKpsZyxWCAy(jSPFfzMmrFu,kHNQhlmEncOIy);rMxTw=oHdH.toString(nHYAAXv" ascii

  condition:
    uint16(0) == 0x6f73 and
    8 of them
}