rule sig_20160314_02ff1bcc40c8426838d63778715d3921 {
  meta:
    description = "datamaliciousorder - file 20160314_02ff1bcc40c8426838d63778715d3921.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "40c3181d2a5df59fb14c482d33bdf69fc4551c0555dd261e4ad7b93fddaad9f5"

  strings:
    $s1  = "var Ze = true  , Ecvw = fHf[7] + fHf[9] + fHf[11];" fullword ascii
    $s2  = "return ToFceED[0] + ToFceED[2] + ToFceED[4] + \".F\" + ToFceED[7] + ToFceED[9] + ToFceED[12] + ToFceED[14];" fullword ascii
    $s3  = "var ToFceED = \"Sc UspBcYS r tCBMfZSKl ipting iCiBNoD nWb ile WFYwMaqxiMxzMT System tg uyTJZ Obj dIykYb ect ChSSkmR KpYNV\".spli" ascii
    $s4  = "var fHf = (\"2.XMLHTTP FuNMtdL rmtpc XML ream St rsXNbnPN AD XhMCxft O oFJr D\").split(\" \");" fullword ascii
    $s5  = "fWqIq.open(IIszW,YnWbC,false);" fullword ascii
    $s6  = "var ToFceED = \"Sc UspBcYS r tCBMfZSKl ipting iCiBNoD nWb ile WFYwMaqxiMxzMT System tg uyTJZ Obj dIykYb ect ChSSkmR KpYNV\".spli" ascii
    $s7  = "if(r>=G.length) {break;}" fullword ascii
    $s8  = "function ggWKwOI(ktbu,hpuJh) {" fullword ascii
    $s9  = "if (lljRk > 168020-915){return true;} else {return false;}" fullword ascii
    $s10 = "function TKTjLDWN() {" fullword ascii
    $s11 = "function ZeZKQ(GPJGVq) {" fullword ascii
    $s12 = "function ghhN(fWqIq,YnWbC,IIszW) {" fullword ascii
    $s13 = "return ggWKwOI(vc,NtTfE[745-739]+NtTfE[967-960]+NtTfE[981-973]);" fullword ascii
    $s14 = "return CkcLD.status;" fullword ascii
    $s15 = "return ktbu.ExpandEnvironmentStrings(hpuJh);" fullword ascii
    $s16 = "function ZVix(CkcLD) {" fullword ascii
    $s17 = "return xKw.size;" fullword ascii
    $s18 = "function EitPOefV(xKw) {" fullword ascii
    $s19 = "if (h >= qtJcy.length) {break;}" fullword ascii
    $s20 = "return eBYXU;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}