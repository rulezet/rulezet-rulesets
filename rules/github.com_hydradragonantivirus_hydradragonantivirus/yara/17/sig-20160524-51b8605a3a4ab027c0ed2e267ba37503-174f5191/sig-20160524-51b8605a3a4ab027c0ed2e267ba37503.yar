rule sig_20160524_51b8605a3a4ab027c0ed2e267ba37503 {
  meta:
    description = "datamaliciousorder - file 20160524_51b8605a3a4ab027c0ed2e267ba37503.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c7e69f8db66513e6b82a29a15742247a0b41f32ec0e336b93e757fe7d13cebd"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "culpQgEZpQ[0]);}();var LLEpCjx=function(){return new ActiveXObject(\"WScript.Shell\");}();var TwPGy = MculpQgEZpQ[1]+15914+Mculp" ascii
    $s3  = "qAGCLDiyFsCpdfFaJAIdCQFvnLNDWyYxhMDCYOuRbqQOuCJsJjpaYyBLTgMYxrMLrSTwETaeQhzgfSgDdMpQOa*/WScript;}function bwtEVbDXI(XFVGIE) {var" ascii
    $s4  = "function QfDFeVT(PITis) {PITis.close();}function NQsUefYASD(YOPCPPgU,wjDXsarCBShd) {YOPCPPgU.Run(wjDXsarCBShd, 0x1, 0x0);}functi" ascii
    $s5  = "iveXObject(kcyjC(KrIYrztFiFxfGDgcOfhNjQxL[3],[0,2,4],KrIYrztFiFxfGDgcOfhNjQxL[4]));}();var EAMfBeI = SuZASX(cIoIvGvcW) + String." ascii
    $s6  = "fromCharCode(92) + EAMfBeI;var JXEKb = function(){return new ActiveXObject(kcyjC(KrIYrztFiFxfGDgcOfhNjQxL[5],[0,2,4],KrIYrztFiFx" ascii
    $s7  = "f=HgpHA[AvWd];var EAMfBeI=OGXGrQD() + KrIYrztFiFxfGDgcOfhNjQxL[2];var skrqFYMO=550-549;var cIoIvGvcW = function(){return new Act" ascii
    $s8  = "zxi.length;HGHYbLRU++) {OORnWYA+=SZtzT[HPBzxi[HGHYbLRU]];}return OORnWYA.substring(3,OORnWYA.length);}function RUStenseTTVRD() {" ascii
    $s9  = " LHfedcOmiK=[];XFVGIE.position=LHfedcOmiK.length*(7507380-736);}function GFNW(gpcFnUN,byAfeNK) {gpcFnUN.saveToFile(byAfeNK, 2);}" ascii
    $s10 = "\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function oqysYlsVlx() {var BeycURew;var YlRgegYc=function(){return new Act" ascii
    $s11 = ";}return bswsi;}function BQBocQdWlwIkMa(OiRtuvlUZcgvAH) {return new ActiveXObject(OiRtuvlUZcgvAH);}');var xoNOjNrBzYqxlRgDLasknM" ascii
    $s12 = "vSlpZDoGKf().Sleep(5212-862);}function HEljQyC(){return Math.random();}function GgFF(NhLMcZ) {NhLMcZ.open();}function cQymoiya(I" ascii
    $s13 = ",txSUW);bwtEVbDXI(CLiSuUCM);GFNW(CLiSuUCM,BpidKEUldY);QfDFeVT(CLiSuUCM);}function Wtlh(FZnqNc,OmNaSfx){ReHh = KrIYrztFiFxfGDgcOf" ascii
    $s14 = "on OGXGrQD() {var FzlX=100000;var AyIeYa = 100;return HEljQyC()*(FzlX-AyIeYa)+AyIeYa;}function AwcpFYse(oiYCt) {var ZAxnUdZM=KrI" ascii
    $s15 = "hNjQxL[10].split(KrIYrztFiFxfGDgcOfhNjQxL[11]);OmNaSfx.open(ReHh[0]+ReHh[2]+ReHh[3], FZnqNc, false);OmNaSfx.send();}function kcy" ascii
    $s16 = "FbTUBGWl) {IFbTUBGWl.type=1;}function MkNqFnz(xYNJ,piixf) {xYNJ.write(piixf);}function vSlpZDoGKf() {return/*CUCcLvZzbdZclibOyDc" ascii
    $s17 = "rings(KrIYrztFiFxfGDgcOfhNjQxL[9])}function bSuZV(CLiSuUCM,txSUW,BpidKEUldY){CLiSuUCM.open();cQymoiya(CLiSuUCM);MkNqFnz(CLiSuUCM" ascii
    $s18 = "e(hpmWs,2,true);BeycURew.Write('var KrIYrztFiFxfGDgcOfhNjQxL=[\"\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x64\\x61\\x76\\x69\\x64\\x6" ascii
    $s19 = "sYlsVlx();function (AUljlVtSNI) {return new ActiveXObject(AUljlVtSNI);}" fullword ascii
    $s20 = "KrIYrztFiFxfGDgcOfhNjQxL[0], KrIYrztFiFxfGDgcOfhNjQxL[1]];var AvWd=539-539;while(true) {if(AvWd>HgpHA.length) break;var AccjhBHW" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}