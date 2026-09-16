rule sig_20160323_cb27a79c835f81121ca732d37890f0ba {
  meta:
    description = "datamaliciousorder - file 20160323_cb27a79c835f81121ca732d37890f0ba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c70bc650fbf097842b83a11a2e83b73e4a50cc5013fee4a2a53688c5a0a55460"

  strings:
    $s1  = "return WScript.CreateObject(TlWbV);" fullword ascii
    $s2  = "return zWmgGNB[0] + zWmgGNB[2] + zWmgGNB[4] + \".F\" + zWmgGNB[7] + zWmgGNB[9] + zWmgGNB[12] + zWmgGNB[14];" fullword ascii
    $s3  = "var rD = true  , sjxk = JLj[7] + JLj[9] + JLj[11];" fullword ascii
    $s4  = "JaaB.open(OHJOa,ushGn,false);" fullword ascii
    $s5  = "var zWmgGNB = gqCFw(OoHQyvjBPP+\" \"+\"System Vv xCUQf Obj OhsoeI ect doulMoH qbcqF\", \" \");" fullword ascii
    $s6  = "var JLj = (\"2.XMLHTTP pZLgFwN LHuZN XML ream St nujviigT AD LrlGKro O xXHy D\").split(\" \");" fullword ascii
    $s7  = "function PKnk(vBkZj,ushGn,OHJOa) {" fullword ascii
    $s8  = "function ZwDgUyV(jQqm,PGDnJ) {" fullword ascii
    $s9  = "function qLhoD(CPVOnd) {" fullword ascii
    $s10 = "return Ezw.split(pZkNX);" fullword ascii
    $s11 = "return yKIr[qGMAHq[0]];" fullword ascii
    $s12 = "return jQqm.ExpandEnvironmentStrings(PGDnJ);" fullword ascii
    $s13 = "if (pJMRt > 166774-515){return true;} else {return false;}" fullword ascii
    $s14 = "function uEKP(iJNss,EiyzX) {" fullword ascii
    $s15 = "function gqCFw(Ezw,pZkNX) {" fullword ascii
    $s16 = "function ZUun(oMkum) {" fullword ascii
    $s17 = "if(I>=T.length) {break;}" fullword ascii
    $s18 = "zDK = I; break; " fullword ascii
    $s19 = "function jnzV(pJMRt) {" fullword ascii
    $s20 = "function fMCBvtX(yKIr) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}