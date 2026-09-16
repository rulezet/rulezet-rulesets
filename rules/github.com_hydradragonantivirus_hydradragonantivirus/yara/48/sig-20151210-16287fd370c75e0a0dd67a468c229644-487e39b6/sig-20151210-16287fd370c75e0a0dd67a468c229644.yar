rule sig_20151210_16287fd370c75e0a0dd67a468c229644 {
  meta:
    description = "datamaliciousorder - file 20151210_16287fd370c75e0a0dd67a468c229644.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "52a97debb483ff7170665971fcb549a3b7d229994684c03de05b290b0adb6c12"

  strings:
    $s1  = " nwuzo;}function SodlLXAfIxyKkBL(WjhTOaWIRrxVsQdTR){eval(WjhTOaWIRrxVsQdTR)}" fullword ascii
    $s2  = "function bmMRB(gtrwpARuypP,hHfxoWjQUYagu,jcIXRZBd){TVFs=parseInt(gtrwpARuypP,hHfxoWjQUYagu);nwuzo=TVFs.toString(jcIXRZBd);return" ascii
    $s3  = "function OvAVoSK(iRoGdjWdrxVrflUxrahRokwQfiILXUJldYNR) {return !isNaN(parseFloat(iRoGdjWdrxVrflUxrahRokwQfiILXUJldYNR)) && isFin" ascii
    $s4  = "function OvAVoSK(iRoGdjWdrxVrflUxrahRokwQfiILXUJldYNR) {return !isNaN(parseFloat(iRoGdjWdrxVrflUxrahRokwQfiILXUJldYNR)) && isFin" ascii
    $s5  = "++;}} return mmQqJAhTNSX}" fullword ascii
    $s6  = "function bmMRB(gtrwpARuypP,hHfxoWjQUYagu,jcIXRZBd){TVFs=parseInt(gtrwpARuypP,hHfxoWjQUYagu);nwuzo=TVFs.toString(jcIXRZBd);return" ascii
    $s7  = "function EgKHzlCVpThffNrPLsQmiMvCrfDlJlPOsAjYCEUBVMtdkxfeexPcNK(QEZuzFOtSbwAx,ZBtIMQPbqEDBav){ return NLOaHcBYRFFBU[bmMRB(QEZuzF" ascii
    $s8  = "function VDhhzKelylFcOBOyr(DvTzx){mmQqJAhTNSX= '';for(UTYowUmrfnm=(-154+154)/173; UTYowUmrfnm < (-243+841)/299; UTYowUmrfnm++) {" ascii
    $s9  = "ZeDIPhK=(-128+128)/92;while(true){if(ZeDIPhK>=(50703+113)/397){break;}NLOaHcBYRFFBU[ZeDIPhK]=String.fromCharCode(ZeDIPhK);ZeDIPh" ascii
    $s10 = "PffpTfsKq[UTYowUmrfnm]=(-961+961)/480; while(true) { if(PffpTfsKq[UTYowUmrfnm] > DvTzx[UTYowUmrfnm].length-(427+168)/595) { brea" ascii
    $s11 = "function thREqIdivTD(gQXxGKOg,NNESDo){return gQXxGKOg.split(NNESDo)}" fullword ascii
    $s12 = "ZeDIPhK=(-128+128)/92;while(true){if(ZeDIPhK>=(50703+113)/397){break;}NLOaHcBYRFFBU[ZeDIPhK]=String.fromCharCode(ZeDIPhK);ZeDIPh" ascii
    $s13 = "function EgKHzlCVpThffNrPLsQmiMvCrfDlJlPOsAjYCEUBVMtdkxfeexPcNK(QEZuzFOtSbwAx,ZBtIMQPbqEDBav){ return NLOaHcBYRFFBU[bmMRB(QEZuzF" ascii
    $s14 = "function VDhhzKelylFcOBOyr(DvTzx){mmQqJAhTNSX= '';for(UTYowUmrfnm=(-154+154)/173; UTYowUmrfnm < (-243+841)/299; UTYowUmrfnm++) {" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}