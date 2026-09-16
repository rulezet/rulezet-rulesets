rule sig_20160321_11c0961cb905171a4c5269870af49295 {
  meta:
    description = "datamaliciousorder - file 20160321_11c0961cb905171a4c5269870af49295.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "433ab5e1a07f9a0c2fa0c9ee11d26af010bf3c1b4f69a89fb310d6fe9efcd739"

  strings:
    $s1  = "return WScript.CreateObject(BPlke);" fullword ascii
    $s2  = "return xqsCgpE[0] + xqsCgpE[2] + xqsCgpE[4] + \".F\" + xqsCgpE[7] + xqsCgpE[9] + xqsCgpE[12] + xqsCgpE[14];" fullword ascii
    $s3  = "var cn = true  , rJtT = WQL[7] + WQL[9] + WQL[11];" fullword ascii
    $s4  = "var xqsCgpE = eiNuS(sjGkozhdSF+\" \"+\"System kq eYLBz Obj BVIqFB ect bgpczps zNFfd\", \" \");" fullword ascii
    $s5  = "var WQL = (\"2.XMLHTTP UVnMXjm tTHby XML ream St JYgVroFx AD nNlxSaQ O Ropm D\").split(\" \");" fullword ascii
    $s6  = "NUtZm.open(YmIZd,WLJHc,false);" fullword ascii
    $s7  = "Frm.CreateFolder(PEdA);" fullword ascii
    $s8  = "if(U>=m.length) {break;}" fullword ascii
    $s9  = "function tlGOt(CqfibO) {" fullword ascii
    $s10 = "function hjsuhanZW(jUUAgzJeSup) {" fullword ascii
    $s11 = "function eiNuS(jhD,okLge) {" fullword ascii
    $s12 = "function JKwbNbraJ(IsVSd) {" fullword ascii
    $s13 = "function mvpd(jXOgz,cmqaZ) {" fullword ascii
    $s14 = "return aSoJ[yXPiAq[0]];" fullword ascii
    $s15 = "if (q >= ApTQK.length) {break;}" fullword ascii
    $s16 = "function QzOh(vUlLJ) {" fullword ascii
    $s17 = "return orOfZQ.position=377-377;" fullword ascii
    $s18 = "var PEdA = usV+JMQzsF[0]+JMQzsF[1];" fullword ascii
    $s19 = "function kjLH(NUtZm,WLJHc,YmIZd) {" fullword ascii
    $s20 = "return RBtpU.status;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}