rule sig_20160313_005eb6c55e1115c619923a47717151ae {
  meta:
    description = "datamaliciousorder - file 20160313_005eb6c55e1115c619923a47717151ae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b8cab5d524be896e27475b45a4d3dde1cfab9ebf96967adceba2bcf6fe9a8ac5"

  strings:
    $s1  = "return lGAxWFx[0] + lGAxWFx[2] + lGAxWFx[4] + \".F\" + lGAxWFx[7] + lGAxWFx[9] + lGAxWFx[12] + lGAxWFx[14];" fullword ascii
    $s2  = "var gB = true  , yXMU = EJr[7] + EJr[9] + EJr[11];" fullword ascii
    $s3  = "JcERR.open(naoWq,jNtgK,false);" fullword ascii
    $s4  = "var EJr = (\"2.XMLHTTP BzaXitP nsNBT XML ream St QLdwhnLM AD nXNoyql O TdLD D\").split(\" \");" fullword ascii
    $s5  = "return mkQWKt.position=365-365;" fullword ascii
    $s6  = "if (jHoxW == 1141-941){return true;} else {return false;}" fullword ascii
    $s7  = "function nZCi(DfuBi) {" fullword ascii
    $s8  = "function EkKja(mkQWKt) {" fullword ascii
    $s9  = "function owAut(aGQXtX) {" fullword ascii
    $s10 = "return new ActiveXObject(aGQXtX);" fullword ascii
    $s11 = "eQb = C; break; " fullword ascii
    $s12 = "if (r >= DfuBi.length) {break;}" fullword ascii
    $s13 = "return SATOy.status;" fullword ascii
    $s14 = "function wiRjvfhO(UaZ) {" fullword ascii
    $s15 = "function mwkh(wiyMV,ecGpl) {" fullword ascii
    $s16 = "function okiL(fZfVd) {" fullword ascii
    $s17 = "function FcXZ(WvjCf) {" fullword ascii
    $s18 = "return eNLs.ExpandEnvironmentStrings(oqwVV);" fullword ascii
    $s19 = "function ooDe(dMDbi,whoZq) {" fullword ascii
    $s20 = "if(C>=c.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}