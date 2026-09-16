rule sig_20151210_a5ab449455d17a1886636576bf919b80 {
  meta:
    description = "datamaliciousorder - file 20151210_a5ab449455d17a1886636576bf919b80.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f52bea6b608d1fe17a25f15b7158ae4581752811adb145434cc693a8dab6d21"

  strings:
    $s1  = "function LXdGZlH(VkjsNbDJLvsUTrymmSrARyCmQAoeCljFICrS) {return !isNaN(parseFloat(VkjsNbDJLvsUTrymmSrARyCmQAoeCljFICrS)) && isFin" ascii
    $s2  = "function LXdGZlH(VkjsNbDJLvsUTrymmSrARyCmQAoeCljFICrS) {return !isNaN(parseFloat(VkjsNbDJLvsUTrymmSrARyCmQAoeCljFICrS)) && isFin" ascii
    $s3  = "function lMleVZlZofjAzDiVd(Uvxyn){pYAfmMsjAuX= '';for(AHpSVqQpJhn=(-237+237)/912; AHpSVqQpJhn < (582+260)/421; AHpSVqQpJhn++) {q" ascii
    $s4  = "function lMleVZlZofjAzDiVd(Uvxyn){pYAfmMsjAuX= '';for(AHpSVqQpJhn=(-237+237)/912; AHpSVqQpJhn < (582+260)/421; AHpSVqQpJhn++) {q" ascii
    $s5  = "function NPhyxsRVjaouuCyLFrrnUblMVPCcjyobdWFgdOpJhpiOtKZWYchqVP(HejXMAGpzzJux,kLCowpJrEBjToo){ return ponrXDGgRoOCc[JgOxz(HejXMA" ascii
    $s6  = "pVWetHSO[AHpSVqQpJhn]=(-532+532)/784; while(true) { if(qpVWetHSO[AHpSVqQpJhn] > Uvxyn[AHpSVqQpJhn].length-(-153+563)/410) { brea" ascii
    $s7  = "function NPhyxsRVjaouuCyLFrrnUblMVPCcjyobdWFgdOpJhpiOtKZWYchqVP(HejXMAGpzzJux,kLCowpJrEBjToo){ return ponrXDGgRoOCc[JgOxz(HejXMA" ascii
    $s8  = "++;}} return pYAfmMsjAuX}" fullword ascii
    $s9  = "function JgOxz(EgdIdMyoXQK,kUeleQIkEXFly,bBufcCDV){rLFh=parseInt(EgdIdMyoXQK,kUeleQIkEXFly);rPIvi=rLFh.toString(bBufcCDV);return" ascii
    $s10 = "function gskVmcDjSMN(DCpOSSsu,NHoVVV){return DCpOSSsu.split(NHoVVV)}" fullword ascii
    $s11 = " rPIvi;}function TZJmsYZaKHbyNhS(qQfjFFrgxkLVGSBhU){eval(qQfjFFrgxkLVGSBhU)}" fullword ascii
    $s12 = "FpEStym=(-384+384)/195;while(true){if(FpEStym>=(122215+921)/962){break;}ponrXDGgRoOCc[FpEStym]=String.fromCharCode(FpEStym);FpES" ascii
    $s13 = "function JgOxz(EgdIdMyoXQK,kUeleQIkEXFly,bBufcCDV){rLFh=parseInt(EgdIdMyoXQK,kUeleQIkEXFly);rPIvi=rLFh.toString(bBufcCDV);return" ascii
    $s14 = "FpEStym=(-384+384)/195;while(true){if(FpEStym>=(122215+921)/962){break;}ponrXDGgRoOCc[FpEStym]=String.fromCharCode(FpEStym);FpES" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}