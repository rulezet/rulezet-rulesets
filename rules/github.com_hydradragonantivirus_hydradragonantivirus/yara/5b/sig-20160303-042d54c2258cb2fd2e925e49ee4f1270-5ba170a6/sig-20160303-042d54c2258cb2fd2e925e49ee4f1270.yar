rule sig_20160303_042d54c2258cb2fd2e925e49ee4f1270 {
  meta:
    description = "datamaliciousorder - file 20160303_042d54c2258cb2fd2e925e49ee4f1270.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "affd0dd00249e3e2605795e4f0483bc51fa1bbca5b0db9744b89c22d15d6ac4c"

  strings:
    $s1  = "var mTUUv = \"yHpKkx twO pt.Shell HlFHcEh Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "return YmaIacz[0] + YmaIacz[2] + YmaIacz[4] + \".F\" + YmaIacz[7] + YmaIacz[9] + YmaIacz[12] + YmaIacz[14];" fullword ascii
    $s3  = "var YcH = (uZb + \"TTP\" + \" UTDJOtX ENHAQ XML ream St dRCXYsVE AD ELGnYoY OD\").split(\" \");" fullword ascii
    $s4  = "var oP = true  , BidH = YcH[7] + \"\" + YcH[9];" fullword ascii
    $s5  = "var YmaIacz = \"Sc EhvhKoz r uRfJLZEym ipting EwvQiyk vbt ile wzEoqwXBbtCFAY System nk bNXvW Obj pLtQta ect RVvItCO\".split(\" " ascii
    $s6  = "TooSd.open(guSJR,VBPIS,false);" fullword ascii
    $s7  = "function GpCg(JYbpf,ESfkG) {" fullword ascii
    $s8  = "if (nXuSt == 870-670){return true;} else {return false;}" fullword ascii
    $s9  = "function XCbh(BDcGU) {" fullword ascii
    $s10 = "function hmli(nXuSt) {" fullword ascii
    $s11 = "function NkXL(XkBvw) {" fullword ascii
    $s12 = "function ArJk(xuEzh) {" fullword ascii
    $s13 = "if (((new Date())>0,7830411888)) {" fullword ascii
    $s14 = "function wuuwJ(PKoQzW) {" fullword ascii
    $s15 = "WlG = p; break; " fullword ascii
    $s16 = "function LhGlYFZ(AGCL) {" fullword ascii
    $s17 = "if(p>=g.length) {break;}" fullword ascii
    $s18 = "function SIsE(FTRRv,RFhIH) {" fullword ascii
    $s19 = "return BDcGU.status;" fullword ascii
    $s20 = "function OaRB(TooSd,VBPIS,guSJR) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}