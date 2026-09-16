rule sig_20160315_87cd1c978a34b4f7e577a171dfcee22f {
  meta:
    description = "datamaliciousorder - file 20160315_87cd1c978a34b4f7e577a171dfcee22f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "99c9ec8353f617bd0a6e8068654dd8537add2f5b8e1c164bc0b6d423379f1ed3"

  strings:
    $s1  = "var Oo = true  , ceRS = zEN[7] + zEN[9] + zEN[11];" fullword ascii
    $s2  = "return QTdcUfy[0] + QTdcUfy[2] + QTdcUfy[4] + \".F\" + QTdcUfy[7] + QTdcUfy[9] + QTdcUfy[12] + QTdcUfy[14];" fullword ascii
    $s3  = "var QTdcUfy = uBBgu(\"Sc hYyQDBJ r AqfCRHxaP ipting bZwaANS bEe ile wbzAmNuOXrieOU System Bu aIZhN Obj vBcWYn ect ruIpedn TsfBX" ascii
    $s4  = "duBQv.open(fBTRT,ZsPJw,false);" fullword ascii
    $s5  = "var QTdcUfy = uBBgu(\"Sc hYyQDBJ r AqfCRHxaP ipting bZwaANS bEe ile wbzAmNuOXrieOU System Bu aIZhN Obj vBcWYn ect ruIpedn TsfBX" ascii
    $s6  = "if(t>=G.length) {break;}" fullword ascii
    $s7  = "function ALrO(pLsSf) {" fullword ascii
    $s8  = "function LBUA(TMbQV,kZkLh) {" fullword ascii
    $s9  = "function uBBgu(yny,JghNf) {" fullword ascii
    $s10 = "function VvmDsvd(WvTX,cTomU) {" fullword ascii
    $s11 = "function BPJOs(RbsIJS) {" fullword ascii
    $s12 = "function fUmW(yQGaa) {" fullword ascii
    $s13 = "function xPYo(duBQv,ZsPJw,fBTRT) {" fullword ascii
    $s14 = "function RiLKAjxp() {" fullword ascii
    $s15 = "return pLsSf.status;" fullword ascii
    $s16 = "return new ActiveXObject(RbsIJS);" fullword ascii
    $s17 = "function yzQcknC(RJXp) {" fullword ascii
    $s18 = "return QKWnJN.position=820-820;" fullword ascii
    $s19 = "return LZBVgbs" fullword ascii
    $s20 = "return VvmDsvd(Zo,dxFDZ[472-466]+dxFDZ[703-696]+dxFDZ[315-307]);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}