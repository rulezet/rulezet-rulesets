rule sig_20160303_a44997f15f37ddf442566517181ae681 {
  meta:
    description = "datamaliciousorder - file 20160303_a44997f15f37ddf442566517181ae681.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f4949ad1412b640ae4ffa72132f2e19f492e0a1a51e6e19c288f9a7f81d1004"

  strings:
    $s1  = "var kxYlF = \"KdxNnG lZN pt.Shell wrwuwce Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "return tDhxbpP[0] + tDhxbpP[2] + tDhxbpP[4] + \".F\" + tDhxbpP[7] + tDhxbpP[9] + tDhxbpP[12] + tDhxbpP[14];" fullword ascii
    $s3  = "var BpE = (mlV + \"TTP\" + \" RsPwhbw oufpG XML ream St VLmIyiSN AD YmYihZl OD\").split(\" \");" fullword ascii
    $s4  = "var Op = true  , vubC = BpE[7] + \"\" + BpE[9];" fullword ascii
    $s5  = "JcvvS.open(TUkmr,KTbDy,false);" fullword ascii
    $s6  = "function TTiI(Rpsix) {" fullword ascii
    $s7  = "function oeeM(FLwPD,mUpkg) {" fullword ascii
    $s8  = "if(G>=q.length) {break;}" fullword ascii
    $s9  = "function HCmwXIt(dMkU) {" fullword ascii
    $s10 = "return FLLpr.status;" fullword ascii
    $s11 = "function MWCB(yuDQq) {" fullword ascii
    $s12 = "return lU.ExpandEnvironmentStrings(kxYlF[6]);" fullword ascii
    $s13 = "return qYzJ.responseBody;" fullword ascii
    $s14 = "function FQAM(JHLnU) {" fullword ascii
    $s15 = "function sweg(zYORn) {" fullword ascii
    $s16 = "function NOTm(nlFfR,ebtao) {" fullword ascii
    $s17 = "function ERPDhDTp() {" fullword ascii
    $s18 = "function Tjcq(KsViX) {" fullword ascii
    $s19 = "if (((new Date())>0,7149381888)) {" fullword ascii
    $s20 = "return SdOPB;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}