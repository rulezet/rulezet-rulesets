rule sig_20151211_5344be5b67667efe31b22c1d277729f8 {
  meta:
    description = "datamaliciousorder - file 20151211_5344be5b67667efe31b22c1d277729f8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7766023cca886f148a2dc20a8673c4918dd096b889d53ad2233078e93e434c05"

  strings:
    $s1  = "function fPEKrfK(MyddrIinaKKLilQSGPLglifZIuPizSIFqtLO) {return !isNaN(parseFloat(MyddrIinaKKLilQSGPLglifZIuPizSIFqtLO)) && isFin" ascii
    $s2  = "function fPEKrfK(MyddrIinaKKLilQSGPLglifZIuPizSIFqtLO) {return !isNaN(parseFloat(MyddrIinaKKLilQSGPLglifZIuPizSIFqtLO)) && isFin" ascii
    $s3  = "function XSdtcLLCDWATlnIDX(QxLWD){qInzJQPwHfu= '';culUmicVSzK=(-390+390)/664; while(true){if(culUmicVSzK >= (1209+715)/962)break" ascii
    $s4  = "function LAWEtBZVBIeIRcAtTiFvLHIOugPKHCpIjtbnEhjXGjycSsPrEffAJV(DEokmgiBPMgta,jCwaMUASuFCMCh){ return SugPY[LdOtw(DEokmgiBPMgta[" ascii
    $s5  = "function LAWEtBZVBIeIRcAtTiFvLHIOugPKHCpIjtbnEhjXGjycSsPrEffAJV(DEokmgiBPMgta,jCwaMUASuFCMCh){ return SugPY[LdOtw(DEokmgiBPMgta[" ascii
    $s6  = "var E=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"50\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s7  = "function LdOtw(hNnxiGBeBZn,MDhVNeFYvbjOy,ZfDxtjYR){ltWK=parseInt(hNnxiGBeBZn,MDhVNeFYvbjOy);uxqBt=ltWK.toString(ZfDxtjYR);return" ascii
    $s8  = "function YMRhcFnqeIx(fDyJPjQW,KbgaLl){return fDyJPjQW.split(KbgaLl)}" fullword ascii
    $s9  = "var u=new Array(\"29\",\"27\",\"2f\",\"2f\",\"29\",\"2b\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s10 = "var E=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"50\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s11 = "function LdOtw(hNnxiGBeBZn,MDhVNeFYvbjOy,ZfDxtjYR){ltWK=parseInt(hNnxiGBeBZn,MDhVNeFYvbjOy);uxqBt=ltWK.toString(ZfDxtjYR);return" ascii
    $s12 = ";uNrnSdVXM[culUmicVSzK]=(-833+833)/705; while(true) { if(uNrnSdVXM[culUmicVSzK] > QxLWD[culUmicVSzK].length-(-397+480)/83) { bre" ascii
    $s13 = "K]++;}culUmicVSzK++;} return qInzJQPwHfu}" fullword ascii
    $s14 = "function XSdtcLLCDWATlnIDX(QxLWD){qInzJQPwHfu= '';culUmicVSzK=(-390+390)/664; while(true){if(culUmicVSzK >= (1209+715)/962)break" ascii
    $s15 = " uxqBt;}function UbhJbrjXsGUsLfv(cLXfYtMgCostIcWwP){eval(cLXfYtMgCostIcWwP)}" fullword ascii
    $s16 = "var u=new Array(\"29\",\"27\",\"2f\",\"2f\",\"29\",\"2b\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}