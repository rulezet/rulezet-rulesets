rule sig_20160309_f054bd297a55caf10764f27b4f274eed {
  meta:
    description = "datamaliciousorder - file 20160309_f054bd297a55caf10764f27b4f274eed.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3de4782b233d3e4cef08e7bc9b9656575af60aa37166835fd667f3f70fc4a57"

  strings:
    $s1  = "return UYoSNgZ[0] + UYoSNgZ[2] + UYoSNgZ[4] + \".F\" + UYoSNgZ[7] + UYoSNgZ[9] + UYoSNgZ[12] + UYoSNgZ[14];" fullword ascii
    $s2  = "var qO = true  , mMCB = vrw[7] + vrw[9] + vrw[11];" fullword ascii
    $s3  = "var UYoSNgZ = \"Sc mbyVjLa r ZpRHLlFYe ipting blBSgZr jze ile eevaIrYLSOpJEB System Rv ZrKnI Obj nwGNge ect rgUeRVk\".split(\" " ascii
    $s4  = "PAsOA.open(fUSwB,TKiLO,false);" fullword ascii
    $s5  = "var vrw = (\"2.XMLHTTP bXFwZsj hOnhU XML ream St VXGxiPMC AD AvRYtft O Fklm D\").split(\" \");" fullword ascii
    $s6  = "function GxBv(kryUz) {" fullword ascii
    $s7  = "function yDvh(CYsYc) {" fullword ascii
    $s8  = "function XBug(pwiGE,pRJTe) {" fullword ascii
    $s9  = "return jOyyl.status;" fullword ascii
    $s10 = "if(W>=e.length) {break;}" fullword ascii
    $s11 = "if (JgYkG == 566-366){return true;} else {return false;}" fullword ascii
    $s12 = "function TvaUCvNjd(bDqBpSXSwBk) {" fullword ascii
    $s13 = "function JroMnrAm(AiWJS,JTPxaR) {" fullword ascii
    $s14 = "if (t >= AjSsb.length) {break;}" fullword ascii
    $s15 = "return tPZcFFE(bN,REVZL[667-661]+REVZL[780-773]+REVZL[858-850]);" fullword ascii
    $s16 = "function JHYKhjDs(iZY) {" fullword ascii
    $s17 = "return MuFec;" fullword ascii
    $s18 = "function jmQy(clPwe) {" fullword ascii
    $s19 = "return sGswCvD" fullword ascii
    $s20 = "function tPZcFFE(lwrb,jeyXw) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}