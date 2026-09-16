rule sig_20160322_3e71f6d424eee16ff28abba26b2b3349 {
  meta:
    description = "datamaliciousorder - file 20160322_3e71f6d424eee16ff28abba26b2b3349.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5225cbf01470becc14504015e4bf332a5a8df4edd532d18316a1f0fba8a50770"

  strings:
    $s1  = "return WScript.CreateObject(NVmuG);" fullword ascii
    $s2  = "var GW = true  , MzDA = vxJ[7] + vxJ[9] + vxJ[11];" fullword ascii
    $s3  = "return pPqehCf[0] + pPqehCf[2] + pPqehCf[4] + \".F\" + pPqehCf[7] + pPqehCf[9] + pPqehCf[12] + pPqehCf[14];" fullword ascii
    $s4  = "var pPqehCf = emCYj(WtEOhAvNZF+\" \"+\"System QK wCvpv Obj FDvYFA ect zPQoBbR BLcwC\", \" \");" fullword ascii
    $s5  = "bqqO.open(RRwQV,TIyqs,false);" fullword ascii
    $s6  = "var vxJ = (\"2.XMLHTTP SbKpZmr muMCl XML ream St rZzCZAbZ AD HqWjXtk O RUIC D\").split(\" \");" fullword ascii
    $s7  = "return CoAqs;" fullword ascii
    $s8  = "return kzsrVBh(Fj,aqBnV[503-497]+aqBnV[261-254]+aqBnV[355-347]);" fullword ascii
    $s9  = "return UAcQcQ.position=681-681;" fullword ascii
    $s10 = "function xnSFC(UAcQcQ) {" fullword ascii
    $s11 = "function KdOK(RbtKu) {" fullword ascii
    $s12 = "function cGAj(Wuorf) {" fullword ascii
    $s13 = "return qNoct.status;" fullword ascii
    $s14 = "if (Shmmw == 440-240){return true;} else {return false;}" fullword ascii
    $s15 = "function zSeV(YzjKN,TIyqs,RRwQV) {" fullword ascii
    $s16 = "function rSJM(nCnrX,RHYPx) {" fullword ascii
    $s17 = "return kAX.split(zfxIs);" fullword ascii
    $s18 = "function BUJN(qNoct) {" fullword ascii
    $s19 = "function cCpgvjCZK(cikgT) {" fullword ascii
    $s20 = "function ngei(Shmmw) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}