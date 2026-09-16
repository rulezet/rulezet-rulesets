rule sig_20160313_18324d474fd85e898bedf89a9196b724 {
  meta:
    description = "datamaliciousorder - file 20160313_18324d474fd85e898bedf89a9196b724.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e4aa09eb3e189a783dc80e9cc571021cfdfc6f1e3beef7d63b4265f46ad223b6"

  strings:
    $s1  = "var dc = true  , hUQz = DWY[7] + DWY[9] + DWY[11];" fullword ascii
    $s2  = "return LgTakgN[0] + LgTakgN[2] + LgTakgN[4] + \".F\" + LgTakgN[7] + LgTakgN[9] + LgTakgN[12] + LgTakgN[14];" fullword ascii
    $s3  = "oVQsA.open(LWpuF,tupan,false);" fullword ascii
    $s4  = "var DWY = (\"2.XMLHTTP uzyOmDx IPGln XML ream St XjbaCKRn AD tRwZNBE O OWkb D\").split(\" \");" fullword ascii
    $s5  = "var LgTakgN = \"Sc MLKWoVf r mFpWcDjMP ipting knVyVJb rPE ile mwnidWbQgekeIf System nR NhFKE Obj kGXtSX ect bvOIRVW\".split(\" " ascii
    $s6  = "return deoudkc" fullword ascii
    $s7  = "if(s>=X.length) {break;}" fullword ascii
    $s8  = "return new ActiveXObject(HJXgSP);" fullword ascii
    $s9  = "return fffMA.status;" fullword ascii
    $s10 = "function XxLHi(HJXgSP) {" fullword ascii
    $s11 = "lFq = s; break; " fullword ascii
    $s12 = "function MoKbMrgq(KkU) {" fullword ascii
    $s13 = "return KkU.size;" fullword ascii
    $s14 = "if (YhJos > 166667-484){return true;} else {return false;}" fullword ascii
    $s15 = "function RZZA(oVQsA,tupan,LWpuF) {" fullword ascii
    $s16 = "function FZGm(tbEDL,yyvcq) {" fullword ascii
    $s17 = "function zrYAgxR(CnKU,GkvQj) {" fullword ascii
    $s18 = "return EVEa.responseBody;" fullword ascii
    $s19 = "function KrPu(XCjPF) {" fullword ascii
    $s20 = "return zrYAgxR(VH,HEneE[642-636]+HEneE[777-770]+HEneE[571-563]);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}