rule sig_20160323_bd473d9c7a157c04f01200d69e6a4229 {
  meta:
    description = "datamaliciousorder - file 20160323_bd473d9c7a157c04f01200d69e6a4229.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ea1436680a6fb38ab04a71037b3b770e7d5dfdacf797f9f833144afc8861fe5"

  strings:
    $s1  = "return WScript.CreateObject(SLmcX);" fullword ascii
    $s2  = "var GaL=((752-751)?\"W\" + sAMBO[744-740]:\"\")+sAMBO[510-508];" fullword ascii
    $s3  = "return UdPLxuI[0] + UdPLxuI[2] + UdPLxuI[4] + \".F\" + UdPLxuI[7] + UdPLxuI[9] + UdPLxuI[12] + UdPLxuI[14];" fullword ascii
    $s4  = "thfc.open(yKYsW,uZgAS,false);" fullword ascii
    $s5  = "var Itg = (\"2.XMLHTTP cVvbvwC gWmxi XML ream St bMwxIOkt AD DczMLQC O xdQQ D\").split(\" \");" fullword ascii
    $s6  = "var UdPLxuI = qQSIp(LjMjofLQsI+\" \"+\"System io jjUJU Obj VpjdpR ect wRhOevN iUByF\", \" \");" fullword ascii
    $s7  = "return pSt.split(mUZBX);" fullword ascii
    $s8  = "return UCzjz;" fullword ascii
    $s9  = "function ItuLUgQz(TOR) {" fullword ascii
    $s10 = "function TxDO(Pmznf) {" fullword ascii
    $s11 = "var sAMBO = qQSIp(ExJfemG+\"HLcE*%TE*MP%*\\\\*vqCdFgoLX*gfjKTO*kQhUgxp*XJjdm\", \"*\");" fullword ascii
    $s12 = "if (Pmznf > 163938-734){return true;} else {return false;}" fullword ascii
    $s13 = "function oYYQ(UapTo) {" fullword ascii
    $s14 = "return BLinD.status;" fullword ascii
    $s15 = "function vfPylpaHN(UaTmezwQFdR) {" fullword ascii
    $s16 = "return TRkdNZ/*n2LZJ99hGrzwU16duKNgr93kZ*/.position=625-625;" fullword ascii
    $s17 = "function Rscc(Emvjd,xhhyz) {" fullword ascii
    $s18 = "function mJmI(lxmsr,uZgAS,yKYsW) {" fullword ascii
    $s19 = "function FdXT(SLmcX) {" fullword ascii
    $s20 = "return pLixgUl(bq,sAMBO[627-621]+sAMBO[579-572]+sAMBO[926-918]);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}