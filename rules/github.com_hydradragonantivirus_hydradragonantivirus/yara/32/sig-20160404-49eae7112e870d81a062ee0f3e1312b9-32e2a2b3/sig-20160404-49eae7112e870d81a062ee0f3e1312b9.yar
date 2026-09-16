rule sig_20160404_49eae7112e870d81a062ee0f3e1312b9 {
  meta:
    description = "datamaliciousorder - file 20160404_49eae7112e870d81a062ee0f3e1312b9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bb2342698984998dd792d38ba1dca7b430037e0c816e29678b653b4a32760124"

  strings:
    $s1  = "var Ad = true  , nXNz = dma[7] + dma[9] + dma[11];" fullword ascii
    $s2  = "return LNnNxIM[0] + LNnNxIM[2] + LNnNxIM[4] + \".F\" + LNnNxIM[7] + LNnNxIM[9] + LNnNxIM[12] + LNnNxIM[14];" fullword ascii
    $s3  = "EFqN.open(sYBch,EcHDD,false);" fullword ascii
    $s4  = "var dma = (\"2.XMLHTTP cCoVMPe bTzfK XML ream St TRFFCzft AD hNNTFPX O cdwL D\").split(\" \");" fullword ascii
    $s5  = "var LNnNxIM = jnCIC(vvKvxArJaU+\" \"+\"System TE pdmAf Obj ZgMlcx ect TgqTidD qrTcc\", \" \");" fullword ascii
    $s6  = "if (VyLym > 178646-101){return true;} else {return false;}" fullword ascii
    $s7  = "function vbZHG(OJwTSo) {" fullword ascii
    $s8  = "function RAMOYy(XnGvzpq) {" fullword ascii
    $s9  = "function TTqVVop(aHEG) {" fullword ascii
    $s10 = "function CPnH(rNuio,RCruW) {" fullword ascii
    $s11 = "function trNH(NhcMf) {" fullword ascii
    $s12 = "function CSsD(ttrkD) {" fullword ascii
    $s13 = "function VuWBVspso(vhpXL) {" fullword ascii
    $s14 = "return DFFr;" fullword ascii
    $s15 = "function VuTK(OlpUo) {" fullword ascii
    $s16 = "function bYQL(SONQy) {" fullword ascii
    $s17 = "function ucTjTIZk(IOhP) {" fullword ascii
    $s18 = "return deb.size;" fullword ascii
    $s19 = "return aHEG[ijMRjm[0]];" fullword ascii
    $s20 = "return BCzFu.status;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}