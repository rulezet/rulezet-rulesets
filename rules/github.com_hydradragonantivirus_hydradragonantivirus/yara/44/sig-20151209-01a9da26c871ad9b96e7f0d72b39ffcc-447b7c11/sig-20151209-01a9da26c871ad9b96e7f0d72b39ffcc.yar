rule sig_20151209_01a9da26c871ad9b96e7f0d72b39ffcc {
  meta:
    description = "datamaliciousorder - file 20151209_01a9da26c871ad9b96e7f0d72b39ffcc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9cd115adcd97ea403cf03b4108cf42db0d695b215e1aed84a21d5fec67a4e7dc"

  strings:
    $s1  = "function QAfdODQ(RUMiIZWVZIyuzCCTSkWhUFMMfCEqcYebHyrX) {return !isNaN(parseFloat(RUMiIZWVZIyuzCCTSkWhUFMMfCEqcYebHyrX)) && isFin" ascii
    $s2  = "function QAfdODQ(RUMiIZWVZIyuzCCTSkWhUFMMfCEqcYebHyrX) {return !isNaN(parseFloat(RUMiIZWVZIyuzCCTSkWhUFMMfCEqcYebHyrX)) && isFin" ascii
    $s3  = "function ngaYNmKOuWz(YgTtHVyG,dcCtzY){return YgTtHVyG.split(dcCtzY)}" fullword ascii
    $s4  = "function IbmCM(NpHqwIJwxpK,ImdLQOyTjGoLT,SYdAkprC){vhow=parseInt(NpHqwIJwxpK,ImdLQOyTjGoLT);jOrMD=vhow.toString(SYdAkprC);return" ascii
    $s5  = "function IbmCM(NpHqwIJwxpK,ImdLQOyTjGoLT,SYdAkprC){vhow=parseInt(NpHqwIJwxpK,ImdLQOyTjGoLT);jOrMD=vhow.toString(SYdAkprC);return" ascii
    $s6  = "} return wbuupnlJFfG}" fullword ascii
    $s7  = " jOrMD;}function blxzXzYJxjXyZhD(hBQaMmrdEzmvVuyAn){eval(hBQaMmrdEzmvVuyAn)}" fullword ascii
    $s8  = "function GJzSPtgpKeIzBnSnVZVoXwnjdbHVugQsxzsdEhbqOCcsBhrTcFpLrU(WPhBuWCAfLzEZ,YcQyFuWluhlstB){ return BkgGe[IbmCM(WPhBuWCAfLzEZ[" ascii
    $s9  = "function GJzSPtgpKeIzBnSnVZVoXwnjdbHVugQsxzsdEhbqOCcsBhrTcFpLrU(WPhBuWCAfLzEZ,YcQyFuWluhlstB){ return BkgGe[IbmCM(WPhBuWCAfLzEZ[" ascii
    $s10 = "TOqnjqW[CacuQfFvGFH]=(-82+82)/964; while(true) { if(NzTOqnjqW[CacuQfFvGFH] > eGbhv[CacuQfFvGFH].length-(135+306)/441) { break; }" ascii
    $s11 = "function NbnzTgixoiUkUvpSc(eGbhv){wbuupnlJFfG= '';for(CacuQfFvGFH=(-494+494)/460; CacuQfFvGFH < (82+502)/292; CacuQfFvGFH++) {Nz" ascii
    $s12 = "function NbnzTgixoiUkUvpSc(eGbhv){wbuupnlJFfG= '';for(CacuQfFvGFH=(-494+494)/460; CacuQfFvGFH < (82+502)/292; CacuQfFvGFH++) {Nz" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}