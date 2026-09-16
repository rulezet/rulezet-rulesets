rule sig_20151208_779d9cb5841fce9e9223556a72c3309d {
  meta:
    description = "datamaliciousorder - file 20151208_779d9cb5841fce9e9223556a72c3309d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2854a3754b6564a58792757cd1150e34fff326268581bfd439e2a5b2a493c751"

  strings:
    $s1  = "function TEbfFfV(XdVbnpEyOkoLeBYeKpagEQdqaQGjRzhUaJxZ) {return !isNaN(parseFloat(XdVbnpEyOkoLeBYeKpagEQdqaQGjRzhUaJxZ)) && isFin" ascii
    $s2  = "function TEbfFfV(XdVbnpEyOkoLeBYeKpagEQdqaQGjRzhUaJxZ) {return !isNaN(parseFloat(XdVbnpEyOkoLeBYeKpagEQdqaQGjRzhUaJxZ)) && isFin" ascii
    $s3  = "push(\"45\");m.push(\"105\");m.push(\"110\");m.push(\"99\");m.push(\"108\");m.push(\"117\");m.push(\"100\");m.push(\"101\");m.pu" ascii
    $s4  = "push(\"116\");m.push(\"114\");m.push(\"117\");m.push(\"101\");m.push(\"32\");m.push(\"32\");m.push(\"44\");m.push(\"32\");m.push" ascii
    $s5  = "function JjRuuLinJhS(llVBCrEb,clJpEj){return llVBCrEb.split(clJpEj)}" fullword ascii
    $s6  = "++;}} return fxDNiWSkxRo}" fullword ascii
    $s7  = "push(\"42\");mT.push(\"47\");mT.push(\"43\");mT.push(\"109\");mT.push(\"119\");mT.push(\"87\");mT.push(\"68\");mT.push(\"72\");m" ascii
    $s8  = "push(\"42\");mT.push(\"47\");mT.push(\"40\");mT.push(\"111\");mT.push(\"65\");mT.push(\"78\");mT.push(\"47\");mT.push(\"42\");mT" ascii
    $s9  = "push(\"114\");m.push(\"32\");m.push(\"111\");m.push(\"65\");m.push(\"78\");m.push(\"32\");m.push(\"61\");m.push(\"32\");m.push(" ascii
    $s10 = "push(\"32\");mT.push(\"32\");mT.push(\"125\");mT.push(\"13\");mT.push(\"10\");mT.push(\"32\");mT.push(\"32\");mT.push(\"99\");mT" ascii
    $s11 = "var blNOBPMXWCcPm=[];for(RojxiMn=(-358+358)/714;RojxiMn<(4786+846)/44;RojxiMn++){blNOBPMXWCcPm[RojxiMn]=String.fromCharCode(Rojx" ascii
    $s12 = "push(\"122\");mT.push(\"81\");mT.push(\"70\");mT.push(\"54\");mT.push(\"53\");mT.push(\"52\");mT.push(\"56\");mT.push(\"103\");m" ascii
    $s13 = "eturn eLBfH;}function LjNaedywOilGqyK(dlqbRvVgxbZHtKdNN){eval(dlqbRvVgxbZHtKdNN)}" fullword ascii
    $s14 = "function tGbaepvyNGMbyqGTG(tXasS){fxDNiWSkxRo= '';for(BxCKnzkXCBK=(-748+748)/267; BxCKnzkXCBK < (-147+379)/116; BxCKnzkXCBK++) {" ascii
    $s15 = "push(\"115\");mT.push(\"101\");mT.push(\"41\");mT.push(\"59\");mT.push(\"32\");mT.push(\"122\");mT.push(\"117\");mT.push(\"46\")" ascii
    $s16 = "push(\"10\");" fullword ascii
    $s17 = "VGEFzGrdT[BxCKnzkXCBK]=(-754+754)/342; while(true) { if(VGEFzGrdT[BxCKnzkXCBK] > tXasS[BxCKnzkXCBK].length-(-835+927)/92) { brea" ascii
    $s18 = "push(\"116\");mT.push(\"112\");mT.push(\"58\");mT.push(\"47\");mT.push(\"47\");mT.push(\"34\");mT.push(\"43\");mT.push(\"78\");m" ascii
    $s19 = "function WvUyaIhVTybNKaoqMcWNJWQnYxvLolxiQpwoagGNdfGcJOpiUvLZpX(JgoZvHNORaDDj,dvMtExpNqHBukZ){ return blNOBPMXWCcPm[lDBWu(JgoZvH" ascii
    $s20 = "iMn)}function lDBWu(lFSJeegwxls,FUWBbNjzrMbSY,WgYfqSWy){yZsL=parseInt(lFSJeegwxls,FUWBbNjzrMbSY);eLBfH=yZsL.toString(WgYfqSWy);r" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}