rule sig_20160310_68eb594249ad4b3f098e473c8106e23a {
  meta:
    description = "datamaliciousorder - file 20160310_68eb594249ad4b3f098e473c8106e23a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "163cd31dc1f54ee17e9b2f4f885be386f6d92a89e4648d07150d6e913ea3dc13"

  strings:
    $s1  = "return xdOnAnz[0] + xdOnAnz[2] + xdOnAnz[4] + \".F\" + xdOnAnz[7] + xdOnAnz[9] + xdOnAnz[12] + xdOnAnz[14];" fullword ascii
    $s2  = "var ou = true  , bBkY = jmL[7] + jmL[9] + jmL[11];" fullword ascii
    $s3  = "AuOMy.open(SEfEX,jHkRY,false);" fullword ascii
    $s4  = "var jmL = (\"2.XMLHTTP RtZAmvM LQoxn XML ream St DWfWpFeS AD pXRgJgD O kgCy D\").split(\" \");" fullword ascii
    $s5  = "var xdOnAnz = \"Sc xsQuWtD r EdMIJSdwq ipting ozWJUwu fto ile vTePYTpKFKhKKw System ij mbsXU Obj BJqbWL ect zpNSeuA\".split(\" " ascii
    $s6  = "function JeEMBnT(vDHW,OyVQJ) {" fullword ascii
    $s7  = "function IJiM(RZdpv) {" fullword ascii
    $s8  = "function DENfncdm(ELZfH,WeXzSp) {" fullword ascii
    $s9  = "return JeEMBnT(RZ,yQXHS[793-787]+yQXHS[886-879]+yQXHS[876-868]);" fullword ascii
    $s10 = "if (jHvQq == 422-222){return true;} else {return false;}" fullword ascii
    $s11 = "function fGqx(jHvQq) {" fullword ascii
    $s12 = "function Lyqb(iCOqm,GuzWb) {" fullword ascii
    $s13 = "return VcM.size;" fullword ascii
    $s14 = "function PEqkKXWl(VcM) {" fullword ascii
    $s15 = "return lQLRGv.position=146-146;" fullword ascii
    $s16 = "function eINw(AuOMy,jHkRY,SEfEX) {" fullword ascii
    $s17 = "return new ActiveXObject(NEibOB);" fullword ascii
    $s18 = "if(S>=a.length) {break;}" fullword ascii
    $s19 = "function HeEW(SqiAD) {" fullword ascii
    $s20 = "function kqrJwfe(oBdN) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}