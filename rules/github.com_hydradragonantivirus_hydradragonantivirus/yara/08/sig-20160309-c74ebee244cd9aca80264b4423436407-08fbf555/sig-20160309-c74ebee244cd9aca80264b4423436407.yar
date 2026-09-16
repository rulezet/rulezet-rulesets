rule sig_20160309_c74ebee244cd9aca80264b4423436407 {
  meta:
    description = "datamaliciousorder - file 20160309_c74ebee244cd9aca80264b4423436407.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "72c29ed6a00d3b9ad927ae12ec2648fd56a3de9405d7c27bf95ec5f7f5e57c18"

  strings:
    $s1  = "Hoieq.open(dKvvH,ZcOmm,false);" fullword ascii
    $s2  = "return WrxHstm[0] + WrxHstm[2] + WrxHstm[4] + \".F\" + WrxHstm[7] + WrxHstm[9] + WrxHstm[12] + WrxHstm[14];" fullword ascii
    $s3  = "var fA = true  , whCw = DzZ[7] + DzZ[9] + DzZ[11];" fullword ascii
    $s4  = "function hhGW(Hoieq,ZcOmm,dKvvH) {" fullword ascii
    $s5  = "var WrxHstm = \"Sc TGkMsXh r oifErYEcp ipting dBwDSKl NLN ile ulgiIzWnqRxBAC System ex nfwyQ Obj YDoYgo ect oPRZLgf\".split(\" " ascii
    $s6  = "function Mckl(kWSUu) {" fullword ascii
    $s7  = "if (iziMS > 179301-321){return true;} else {return false;}" fullword ascii
    $s8  = "function Lvpg(TxhyA) {" fullword ascii
    $s9  = "xJR = l; break; " fullword ascii
    $s10 = "return JqkciRe" fullword ascii
    $s11 = "function wdaGPJY(uCBJ) {" fullword ascii
    $s12 = "if(l>=m.length) {break;}" fullword ascii
    $s13 = "return LqixE.status;" fullword ascii
    $s14 = "function EQHvu(SUgapA) {" fullword ascii
    $s15 = "return new ActiveXObject(SUgapA);" fullword ascii
    $s16 = "function iPxQ(WThRH) {" fullword ascii
    $s17 = "return kIB.size;" fullword ascii
    $s18 = "function fOGRExdB(kIB) {" fullword ascii
    $s19 = "return bD.ExpandEnvironmentStrings(dJgnZ[6]+dJgnZ[7]+dJgnZ[8]);" fullword ascii
    $s20 = "function AdUU(LqixE) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}