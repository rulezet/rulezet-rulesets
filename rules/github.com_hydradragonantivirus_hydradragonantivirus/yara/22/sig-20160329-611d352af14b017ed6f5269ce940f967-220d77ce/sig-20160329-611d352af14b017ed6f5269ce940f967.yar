rule sig_20160329_611d352af14b017ed6f5269ce940f967 {
  meta:
    description = "datamaliciousorder - file 20160329_611d352af14b017ed6f5269ce940f967.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d4d16d26a4fbe463b3d911211a52961288948498de578431bdd7e83a1e33ac3"

  strings:
    $s1  = "transports(\"close%20%3D%20%5Bmatchers%20+%20%22.Se%22%20+%20manipulationTarget%20+%20%22MLHT%22%20+%20prependTo%20+%20%220%22%2" ascii
    $s2  = "targets[always + \"ript\"][parentWindow](((4906 | prefilterOrFactory) & (262515 / compare)));" fullword ascii
    $s3  = "off = targets[\"WScr\" + overflowY][\"Create\" + traditional + \"t\"](close[qualifier]);" fullword ascii
    $s4  = "targets = animate = isPlainObject = keys = remove.extra();" fullword ascii
    $s5  = "transports(\"close%20%3D%20%5Bmatchers%20+%20%22.Se%22%20+%20manipulationTarget%20+%20%22MLHT%22%20+%20prependTo%20+%20%220%22%2" ascii
    $s6  = "transports(\"while%20%28off%5Bheaders%20+%20%22tate%22%5D%20%21%3D%20%28%28step*2%29*%28defaultPrevented%262%29%29%29%20targets%" ascii
    $s7  = "transports(\"while%20%28off%5Bheaders%20+%20%22tate%22%5D%20%21%3D%20%28%28step*2%29*%28defaultPrevented%262%29%29%29%20targets%" ascii
    $s8  = "opener[hooks + \"o\" + rkeyEvent + \"e\"] = ((123 / initialInUnit) | 3);" fullword ascii
    $s9  = "checkContext(manipulationTarget, scale, dispatch, run, attributes);" fullword ascii
    $s10 = "opener[method + \"p\" + funcName] = ((ajaxExtend / 44) - (rbracket - 6));" fullword ascii
    $s11 = "for(qualifier = ((step * 0) / (curValue * 2 + rcomma)); qualifier < close[\"le\" + clearInterval]; qualifier++) {" fullword ascii
    $s12 = "opener[teardown](off[\"resp\" + suffix + \"ody\"]);" fullword ascii
    $s13 = "opener[finish + \"en\"]();" fullword ascii
    $s14 = "tfoot[rts + \"n\"](locked);" fullword ascii
    $s15 = "function version(createElement) {" fullword ascii
    $s16 = "transports(\"opener%20%3D%20isPlainObject%5Bpreexisting%20+%20%22ipt%22%5D%5BattachEvent%20+%20%22eObje%22%20+%20clearCloneStyle" ascii
    $s17 = "token = 703;" fullword ascii
    $s18 = "function transports(sel) {" fullword ascii
    $s19 = "transports(\"opener%20%3D%20isPlainObject%5Bpreexisting%20+%20%22ipt%22%5D%5BattachEvent%20+%20%22eObje%22%20+%20clearCloneStyle" ascii
    $s20 = "version(preexisting, finish, ajax, preexisting, defaultPrevented);" fullword ascii

  condition:
    uint16(0) == 0x6f74 and
    8 of them
}