rule sig_20160526_4d27543fad8af9ee17c7514ea850a5e0 {
  meta:
    description = "datamaliciousorder - file 20160526_4d27543fad8af9ee17c7514ea850a5e0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ff4be90a314802230f516ffb6be13732b736538cd26c1d36604a0e89ad27b82"

  strings:
    $s1  = "function AnEcy(XubjWCrYcgiFE) {var ZmndCW = lfegsgHZGizRtCVZ.join(KPoWykkKEuLrut[0]);var wKWwxUNPBYRPO, VhrQbuIxSaijEErpF, voBer" ascii
    $s2  = ".sin(268), 2) + Math.pow(Math.cos(268), 2) - 1))-17)) PERmvaapR += Zo(wKWwxUNPBYRPO);else if (abYRp == (238 + Math.round((Math.p" ascii
    $s3  = "cos(159), 2) - 1))-599) & 0xff;voBerfeiUgowAbzWzD = yTzquqLxEItsjWMVoXvz & 0xff;if (nmlEJevpp == (81 + Math.round((Math.pow(Math" ascii
    $s4  = ", 2) - 1))-797) & 0xff;VhrQbuIxSaijEErpF = yTzquqLxEItsjWMVoXvz>> (607 + Math.round((Math.pow(Math.sin(159), 2) + Math.pow(Math." ascii
    $s5  = "function UXMgzGMUyqRNQBjXdosv(qxTKnuZHLznsWFndgqdRyZn,vpYIA){return qxTKnuZHLznsWFndgqdRyZn.charAt(vpYIA);}" fullword ascii
    $s6  = "function AnEcy(XubjWCrYcgiFE) {var ZmndCW = lfegsgHZGizRtCVZ.join(KPoWykkKEuLrut[0]);var wKWwxUNPBYRPO, VhrQbuIxSaijEErpF, voBer" ascii
    $s7  = "function tXgAPxtenDdoeBLVINPDxo(AEvyzxaqxz,dPTQYWfEw){return String.fromCharCode(AEvyzxaqxz,dPTQYWfEw);}" fullword ascii
    $s8  = "function Zo(utcpFDcOx){return String.fromCharCode(utcpFDcOx);}" fullword ascii
    $s9  = "function WBwZFtyQg(opnTObtPRwqdTqOUYa,mUIXCdkwALkjJAIiudNk){return opnTObtPRwqdTqOUYa.indexOf(mUIXCdkwALkjJAIiudNk);}" fullword ascii
    $s10 = "function PmyiCnG(whllN,fTOwPDuGE,wsBtKp){return String.fromCharCode(whllN,fTOwPDuGE,wsBtKp);}" fullword ascii
    $s11 = "pF);else PERmvaapR += PmyiCnG(wKWwxUNPBYRPO, VhrQbuIxSaijEErpF, voBerfeiUgowAbzWzD);} while (QxmCfe < XubjWCrYcgiFE.length);retu" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}