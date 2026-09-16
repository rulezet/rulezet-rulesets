rule sig_20160411_c82ce59a990349a7d533cbf3e74d2a1b {
  meta:
    description = "datamaliciousorder - file 20160411_c82ce59a990349a7d533cbf3e74d2a1b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bdc906b30160ef04171a41d0f87aa962ebfd03b4bdba2b378b2d5d240b21461f"

  strings:
    $s1  = "return GSbZOBd[0] + GSbZOBd[2] + GSbZOBd[4] + \".F\" + GSbZOBd[7] + GSbZOBd[9] + GSbZOBd[12] + GSbZOBd[14];" fullword ascii
    $s2  = "var aN = true  , ADlj = KrJ[7] + KrJ[9] + KrJ[11];" fullword ascii
    $s3  = "aiPb.open(UshuG,zdAgN,false);" fullword ascii
    $s4  = "var KrJ = (\"2.XMLHTTP tfmdaUB WTStt XML ream St eiOixGIt AD SJEKwOk O TyjL D\").split(\" \");" fullword ascii
    $s5  = "function PbfV(TWYIy,pJqrb) {" fullword ascii
    $s6  = "function GfuJ(QvpjV) {" fullword ascii
    $s7  = "function xZDHzCt(rAlE,UOTae) {" fullword ascii
    $s8  = "return lOWzbH[SjJu[842-842]]=219-219;" fullword ascii
    $s9  = "function lPCZ(KsNMl) {" fullword ascii
    $s10 = "function yjORADF(NcKz) {" fullword ascii
    $s11 = "ajD = z; break; " fullword ascii
    $s12 = "function NaQllWoA(oqM) {" fullword ascii
    $s13 = "if(z>=x.length) {break;}" fullword ascii
    $s14 = "return oqM.size;" fullword ascii
    $s15 = "function WtYle(ahocDU) {" fullword ascii
    $s16 = "function lpUI(aBlaX) {" fullword ascii
    $s17 = "return icnne;" fullword ascii
    $s18 = "if (j >= aBlaX.length) {break;}" fullword ascii
    $s19 = "return xZDHzCt(Ab,xWmglq+DWKDc[359-351]);" fullword ascii
    $s20 = "function TiNau(VNf,RDqJO) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}