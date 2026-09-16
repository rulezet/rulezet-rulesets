rule sig_20160303_3be2d17976ddd1a603969ca30527fd26 {
  meta:
    description = "datamaliciousorder - file 20160303_3be2d17976ddd1a603969ca30527fd26.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea8db7526bba9f04049e486a2965dcb96f43e81b6ad74c2b85dc045b27663f78"

  strings:
    $s1  = "var ASzit = \"dJduQH vSk pt.Shell WMSunBQ Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "var xWh = (EiW + \"TTP\" + \" GDsLBLT KjbTG XML ream St yuAVWzMp AD ZrHwAOn OD\").split(\" \");" fullword ascii
    $s3  = "var Fs = true  , UDqx = xWh[7] + \"\" + xWh[9];" fullword ascii
    $s4  = "return KUEORQu[0] + KUEORQu[2] + KUEORQu[4] + \".F\" + KUEORQu[7] + KUEORQu[9] + KUEORQu[12] + KUEORQu[14];" fullword ascii
    $s5  = "FSawi.open(VsLwQ,uJFXM,false);" fullword ascii
    $s6  = "var KUEORQu = \"Sc uXfRTpW r dYYvyoOvP ipting mbbwqqf vKY ile aaojyGFnXkfYJh System iK lNdud Obj uQDsWB ect TCjEtLO\".split(\" " ascii
    $s7  = "function GcDn(YwPvK,debDV) {" fullword ascii
    $s8  = "adX = X; break; " fullword ascii
    $s9  = "function gZFPTaOp() {" fullword ascii
    $s10 = "function NEXo(xAgVO) {" fullword ascii
    $s11 = "function OXyW(GzUAf) {" fullword ascii
    $s12 = "function bTbwgtrVr(rKLkH,LUUzg,SHTqB) {" fullword ascii
    $s13 = "if (((new Date())>0,7457405888)) {" fullword ascii
    $s14 = "if (ecftY == 719-519){return true;} else {return false;}" fullword ascii
    $s15 = "function Jbyk(ecftY) {" fullword ascii
    $s16 = "return pg.ExpandEnvironmentStrings(ASzit[6]);" fullword ascii
    $s17 = "function fbLx(GhvNY) {" fullword ascii
    $s18 = "if(X>=A.length) {break;}" fullword ascii
    $s19 = "function GWXEpTY(hUvr) {" fullword ascii
    $s20 = "if (GhvNY > 159046-204){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}