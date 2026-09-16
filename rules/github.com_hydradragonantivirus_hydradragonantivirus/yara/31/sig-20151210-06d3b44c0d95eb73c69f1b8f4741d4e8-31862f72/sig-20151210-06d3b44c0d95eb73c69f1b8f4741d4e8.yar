rule sig_20151210_06d3b44c0d95eb73c69f1b8f4741d4e8 {
  meta:
    description = "datamaliciousorder - file 20151210_06d3b44c0d95eb73c69f1b8f4741d4e8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "00627d6ce2991d24ee5f9a32b7fccb71f04e59970e6fb6a18ac2476bd639fe68"

  strings:
    $s1  = "function WUFcXHoLQQUmShRZzdyveqYzjjypKaHdSJjQpIzZxqPbtfEQOSpkdv(WxnxJMjexLPrf,zsFPmIDHlbLdzU){ return NpMMn[swMxM(WxnxJMjexLPrf[" ascii
    $s2  = "function swMxM(FNcGaXTaivr,DmjgcxjfVgGnL,TlGsoLDq){ajzR=parseInt(FNcGaXTaivr,DmjgcxjfVgGnL);FpxyQ=ajzR.toString(TlGsoLDq);return" ascii
    $s3  = "function jsuVvhFSvJgAmBHyS(KgbIO){cykqaYeSnFc= '';for(kkXbYcppfxR=(-179+179)/555; kkXbYcppfxR < (689+747)/718; kkXbYcppfxR++) {M" ascii
    $s4  = "function jsuVvhFSvJgAmBHyS(KgbIO){cykqaYeSnFc= '';for(kkXbYcppfxR=(-179+179)/555; kkXbYcppfxR < (689+747)/718; kkXbYcppfxR++) {M" ascii
    $s5  = "function YtIfzkIZtGi(WyYnJmYQ,PUnPTK){return WyYnJmYQ.split(PUnPTK)}" fullword ascii
    $s6  = "function swMxM(FNcGaXTaivr,DmjgcxjfVgGnL,TlGsoLDq){ajzR=parseInt(FNcGaXTaivr,DmjgcxjfVgGnL);FpxyQ=ajzR.toString(TlGsoLDq);return" ascii
    $s7  = "function WUFcXHoLQQUmShRZzdyveqYzjjypKaHdSJjQpIzZxqPbtfEQOSpkdv(WxnxJMjexLPrf,zsFPmIDHlbLdzU){ return NpMMn[swMxM(WxnxJMjexLPrf[" ascii
    $s8  = "} return cykqaYeSnFc}" fullword ascii
    $s9  = " FpxyQ;}function snzoGqGfBKxFutw(hfdDUMlXmPJhbwDyQ){eval(hfdDUMlXmPJhbwDyQ)}" fullword ascii
    $s10 = "LintQMTQ[kkXbYcppfxR]=(-290+290)/814; while(true) { if(MLintQMTQ[kkXbYcppfxR] > KgbIO[kkXbYcppfxR].length-(77+560)/637) { break;" ascii
    $s11 = "function MSTJEev(TXxHwVMXhPrjaXgxzCLChWOEhVLvtcaxkJWN) {return !isNaN(parseFloat(TXxHwVMXhPrjaXgxzCLChWOEhVLvtcaxkJWN)) && isFin" ascii
    $s12 = "function MSTJEev(TXxHwVMXhPrjaXgxzCLChWOEhVLvtcaxkJWN) {return !isNaN(parseFloat(TXxHwVMXhPrjaXgxzCLChWOEhVLvtcaxkJWN)) && isFin" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}