rule sig_20151209_37fc78817c76a6c690a665c800554455 {
  meta:
    description = "datamaliciousorder - file 20151209_37fc78817c76a6c690a665c800554455.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "38f06c384b66bd5c1b3d3383f7ec7366c0d2e2624769e2efefcdd9ead04b00e7"

  strings:
    $s1  = "function vnyikcq(KwJueSxpyDUeTeSBozmLEUzfrDtmbRPAPxpF) {return !isNaN(parseFloat(KwJueSxpyDUeTeSBozmLEUzfrDtmbRPAPxpF)) && isFin" ascii
    $s2  = "function vnyikcq(KwJueSxpyDUeTeSBozmLEUzfrDtmbRPAPxpF) {return !isNaN(parseFloat(KwJueSxpyDUeTeSBozmLEUzfrDtmbRPAPxpF)) && isFin" ascii
    $s3  = "turn RoPbMVarhGU}" fullword ascii
    $s4  = "function NVmpZWZhKxHOHtWKo(mAYII){RoPbMVarhGU= '';for(lXIGzpSRrex=(-70+70)/547; lXIGzpSRrex < (-135+179)/22; lXIGzpSRrex++) {aGY" ascii
    $s5  = " jgcXv;}function PfZZHpahIwBIMrp(GrrIAKIhKmHWtfcEA){eval(GrrIAKIhKmHWtfcEA)}" fullword ascii
    $s6  = "function HmndyoUdPnZOnDusmitaJmWiUxriqnMeYVPMtLEBpuDCxfKKbvoPlB(HSloNKZFcqOxU,NwfkYyqSvHAIDh){ return UHdaY[QaUBw(HSloNKZFcqOxU[" ascii
    $s7  = "function HmndyoUdPnZOnDusmitaJmWiUxriqnMeYVPMtLEBpuDCxfKKbvoPlB(HSloNKZFcqOxU,NwfkYyqSvHAIDh){ return UHdaY[QaUBw(HSloNKZFcqOxU[" ascii
    $s8  = "function JImHIBByAHd(NVPsKNQM,tOhhoD){return NVPsKNQM.split(tOhhoD)}" fullword ascii
    $s9  = "function QaUBw(MbYaoFyEwzU,EzhrCcYkABbRF,yYSLxBcZ){pZeO=parseInt(MbYaoFyEwzU,EzhrCcYkABbRF);jgcXv=pZeO.toString(yYSLxBcZ);return" ascii
    $s10 = "function QaUBw(MbYaoFyEwzU,EzhrCcYkABbRF,yYSLxBcZ){pZeO=parseInt(MbYaoFyEwzU,EzhrCcYkABbRF);jgcXv=pZeO.toString(yYSLxBcZ);return" ascii
    $s11 = "TldMpp[lXIGzpSRrex]=(-33+33)/942; while(true) { if(aGYTldMpp[lXIGzpSRrex] > mAYII[lXIGzpSRrex].length-(386+58)/444) { break; } i" ascii
    $s12 = "function NVmpZWZhKxHOHtWKo(mAYII){RoPbMVarhGU= '';for(lXIGzpSRrex=(-70+70)/547; lXIGzpSRrex < (-135+179)/22; lXIGzpSRrex++) {aGY" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}