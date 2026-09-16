rule sig_20160310_c324599a413ab8e0a3aaa44b21933a36 {
  meta:
    description = "datamaliciousorder - file 20160310_c324599a413ab8e0a3aaa44b21933a36.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "095c447716ed33a2def9e4d31b590a6ecd8fe004459bebf6180de8ee85b2669f"

  strings:
    $s1  = "return QzpbGij[0] + QzpbGij[2] + QzpbGij[4] + \".F\" + QzpbGij[7] + QzpbGij[9] + QzpbGij[12] + QzpbGij[14];" fullword ascii
    $s2  = "var Ng = true  , NgbD = Dnr[7] + Dnr[9] + Dnr[11];" fullword ascii
    $s3  = "var Dnr = (\"2.XMLHTTP CJmfngs iCHfG XML ream St sAZmnVnJ AD xnjTnIA O WZMI D\").split(\" \");" fullword ascii
    $s4  = "var QzpbGij = \"Sc NZJsVHv r sCTiqDHBv ipting RQdkJUI nJx ile QZcvAGUtUwyTXa System Wk SqMAm Obj NcFuUo ect sAVquKA\".split(\" " ascii
    $s5  = "GyjbL.open(Geals,EGQkm,false);" fullword ascii
    $s6  = "return vlzB.ExpandEnvironmentStrings(BJQKB);" fullword ascii
    $s7  = "return new ActiveXObject(eubdUF);" fullword ascii
    $s8  = "return wYfArQG(EA,XqUFd[446-440]+XqUFd[577-570]+XqUFd[237-229]);" fullword ascii
    $s9  = "if (mSUHJ == 899-699){return true;} else {return false;}" fullword ascii
    $s10 = "function vpLxSCtHw(hVcwm,qOsYN,ZDEbt,axVA) {" fullword ascii
    $s11 = "function YbyJ(NbuiA) {" fullword ascii
    $s12 = "function wzIx(KnFUr,VhZfu) {" fullword ascii
    $s13 = "function vXnK(zOFBH) {" fullword ascii
    $s14 = "function FkyQVpej(lDkSX,RttlBA) {" fullword ascii
    $s15 = "function ebVm(mSUHJ) {" fullword ascii
    $s16 = "return WqZzGlB" fullword ascii
    $s17 = "function PadJ(MHMmR) {" fullword ascii
    $s18 = "if(l>=L.length) {break;}" fullword ascii
    $s19 = "function hZjF(tulPp,MBtGy) {" fullword ascii
    $s20 = "function HDHG(FIKev) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}