rule sig_20160310_cc5422265a6a01dfeb8bcb1364eef2ff {
  meta:
    description = "datamaliciousorder - file 20160310_cc5422265a6a01dfeb8bcb1364eef2ff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "828d1eed9c9cde1e3f4e72e9e3155912f4b617de834bc066bc21fc79c9d75c64"

  strings:
    $s1  = "var vK = true  , KzzX = HIa[7] + HIa[9] + HIa[11];" fullword ascii
    $s2  = "return EdYhEqI[0] + EdYhEqI[2] + EdYhEqI[4] + \".F\" + EdYhEqI[7] + EdYhEqI[9] + EdYhEqI[12] + EdYhEqI[14];" fullword ascii
    $s3  = "hDTSL.open(lZjkT,MPQmW,false);" fullword ascii
    $s4  = "var EdYhEqI = \"Sc qSWHpBu r eAoNDpBjH ipting qTLoSoh uQB ile CtZkDggQeFvpch System Rr kwTeK Obj SmohId ect MUHfcGp\".split(\" " ascii
    $s5  = "var HIa = (\"2.XMLHTTP iIGapNR DqsBk XML ream St MrGVkVhs AD HItRrSV O iPLl D\").split(\" \");" fullword ascii
    $s6  = "function VOflp(WKrttA) {" fullword ascii
    $s7  = "function EFmCCZhfM(wupli,ZHmek,Pnyre,LiBH) {" fullword ascii
    $s8  = "function zSUsTpozh(CwIjRfDhxUB) {" fullword ascii
    $s9  = "function aBGa(Eqfbk) {" fullword ascii
    $s10 = "return VbbDoGm(wr,fPBNI[158-152]+fPBNI[237-230]+fPBNI[230-222]);" fullword ascii
    $s11 = "return OpX.size;" fullword ascii
    $s12 = "function UOKiLUqu(OpX) {" fullword ascii
    $s13 = "function RyBchZiT(EOhFS,eloDDz) {" fullword ascii
    $s14 = "function VbbDoGm(UwxC,jhreU) {" fullword ascii
    $s15 = "return WUuT.responseBody;" fullword ascii
    $s16 = "return OBetT.status;" fullword ascii
    $s17 = "return lwfxWuo" fullword ascii
    $s18 = "return new ActiveXObject(WKrttA);" fullword ascii
    $s19 = "function UHbZ(WBFjp) {" fullword ascii
    $s20 = "if (v >= Eqfbk.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}