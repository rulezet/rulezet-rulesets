rule sig_20160310_530d76965ba7f5561684cb0df4c80fbc {
  meta:
    description = "datamaliciousorder - file 20160310_530d76965ba7f5561684cb0df4c80fbc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b421b84e9aeb13869f42f0431d28a66c8d98f1f5bcf5453f48c3b1c86f9f2243"

  strings:
    $s1  = "return PdumiLj[0] + PdumiLj[2] + PdumiLj[4] + \".F\" + PdumiLj[7] + PdumiLj[9] + PdumiLj[12] + PdumiLj[14];" fullword ascii
    $s2  = "var ad = true  , BkBw = Pxb[7] + Pxb[9] + Pxb[11];" fullword ascii
    $s3  = "var PdumiLj = \"Sc tgxEglI r nNBuMnHsi ipting JhsDfev kHb ile xPOZMhLJlNShKH System ds vzJCO Obj XEnKpv ect JztMgHV\".split(\" " ascii
    $s4  = "QEbVb.open(wKoDx,HBzfb,false);" fullword ascii
    $s5  = "var Pxb = (\"2.XMLHTTP HxxtmnY SJSHU XML ream St pdihqfDa AD vJYfDhd O jntb D\").split(\" \");" fullword ascii
    $s6  = "function iPxJ(ykzav) {" fullword ascii
    $s7  = "function JRZOkvf(ZxvT,xddyS) {" fullword ascii
    $s8  = "return ZxvT.ExpandEnvironmentStrings(xddyS);" fullword ascii
    $s9  = "function UZCIphSO() {" fullword ascii
    $s10 = "function ZsAT(TzKNk) {" fullword ascii
    $s11 = "function ZjfVZXNS(Lmxxd,qLxefk) {" fullword ascii
    $s12 = "return NcxxB;" fullword ascii
    $s13 = "function GpzUKVLs(NPM) {" fullword ascii
    $s14 = "return NPM.size;" fullword ascii
    $s15 = "if (beUdx == 453-253){return true;} else {return false;}" fullword ascii
    $s16 = "function SXoB(gyooL,uUVul) {" fullword ascii
    $s17 = "if(X>=C.length) {break;}" fullword ascii
    $s18 = "function zCTB(EMSLd) {" fullword ascii
    $s19 = "return new ActiveXObject(tGjUbx);" fullword ascii
    $s20 = "function Hvyk(ULoOo) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}