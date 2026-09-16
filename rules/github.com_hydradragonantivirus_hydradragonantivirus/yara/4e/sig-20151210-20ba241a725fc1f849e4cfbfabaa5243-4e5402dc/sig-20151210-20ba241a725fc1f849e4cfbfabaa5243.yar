rule sig_20151210_20ba241a725fc1f849e4cfbfabaa5243 {
  meta:
    description = "datamaliciousorder - file 20151210_20ba241a725fc1f849e4cfbfabaa5243.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "edc8bb1fe82d75b52ec7bb16dbd53812584b20e003eff6a929d2d0ff647e0070"

  strings:
    $s1  = "function bPYeKfD(MSGZJXOPhsGIKdSvsVdnWqbONgPsmrWjYIwr) {return !isNaN(parseFloat(MSGZJXOPhsGIKdSvsVdnWqbONgPsmrWjYIwr)) && isFin" ascii
    $s2  = "function bPYeKfD(MSGZJXOPhsGIKdSvsVdnWqbONgPsmrWjYIwr) {return !isNaN(parseFloat(MSGZJXOPhsGIKdSvsVdnWqbONgPsmrWjYIwr)) && isFin" ascii
    $s3  = "function fgsvJ(hCocDRiQhdz,XhsvRJqrvfBxA,SnLKSGxD){FYQG=parseInt(hCocDRiQhdz,XhsvRJqrvfBxA);dqEtq=FYQG.toString(SnLKSGxD);return" ascii
    $s4  = "function pHuSPZSgHIsOoisbh(dSdBB){FVPrxoJQbot= '';for(htOaLqfiRYA=(-369+369)/476; htOaLqfiRYA < (1067+787)/927; htOaLqfiRYA++) {" ascii
    $s5  = " return FVPrxoJQbot}" fullword ascii
    $s6  = "function LpuMGtSdDkYlvIdskwbcdnPxmNzlPbpRNhkTUbtNzyYkvMGjxyhyyq(pzgknKOSgUQxs,jPGiPfQZQVQrot){ return ynSTH[fgsvJ(pzgknKOSgUQxs[" ascii
    $s7  = " dqEtq;}function DmUatdAThykMtwj(urdJcgKRXwSdVzhFg){eval(urdJcgKRXwSdVzhFg)}" fullword ascii
    $s8  = "function fgsvJ(hCocDRiQhdz,XhsvRJqrvfBxA,SnLKSGxD){FYQG=parseInt(hCocDRiQhdz,XhsvRJqrvfBxA);dqEtq=FYQG.toString(SnLKSGxD);return" ascii
    $s9  = "function pHuSPZSgHIsOoisbh(dSdBB){FVPrxoJQbot= '';for(htOaLqfiRYA=(-369+369)/476; htOaLqfiRYA < (1067+787)/927; htOaLqfiRYA++) {" ascii
    $s10 = "function LpuMGtSdDkYlvIdskwbcdnPxmNzlPbpRNhkTUbtNzyYkvMGjxyhyyq(pzgknKOSgUQxs,jPGiPfQZQVQrot){ return ynSTH[fgsvJ(pzgknKOSgUQxs[" ascii
    $s11 = "function DPsvkmIEpiJ(QItOkTIK,xJVwQJ){return QItOkTIK.split(xJVwQJ)}" fullword ascii
    $s12 = "CZjuoFglS[htOaLqfiRYA]=(-31+31)/450; while(true) { if(CZjuoFglS[htOaLqfiRYA] > dSdBB[htOaLqfiRYA].length-(-115+767)/652) { break" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}