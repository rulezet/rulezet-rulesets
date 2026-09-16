rule sig_20160524_8e2fbe72852483c7da12bffa0a59a29a {
  meta:
    description = "datamaliciousorder - file 20160524_8e2fbe72852483c7da12bffa0a59a29a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "30e39d32ebfdebf8ef75b33792d0e7c265a5387b1160d55fc118d93651b10abe"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "();}function DOtMuYuFqa(TAwhIvrd,eOgZaEtINpko) {TAwhIvrd.Run(eOgZaEtINpko, 0x1, 0x0);}function JbBLjIp() {var DdQc=100000;var rV" ascii
    $s3  = "ZqdPc++){xeVjM+=mhEOITNI.charAt(Math.floor(Math.random()*mhEOITNI.length));}return xeVjM;}function yPdDLnFVaNcZwA(mMEnAIDkKJXdiq" ascii
    $s4  = "){return new ActiveXObject(LjoEP(orVquq[3],[0,2,4],orVquq[4]));}();var zERupxf = MmKdlI(CfdrAUePb) + String.fromCharCode(92) + z" ascii
    $s5  = "J>zyJUS.length) break;var KAcXwHvxG=zyJUS[YVSJ];var zERupxf=JbBLjIp() + orVquq[2];var qOsLAgfH=874-873;var CfdrAUePb = function(" ascii
    $s6  = "XKpTFXKYJuIEvCxETzG[0]);}();var wcacFZNYLw=function(){return new ActiveXObject(\"WScript.Shell\");}();var zJsASAQgkp = jCFXKpTFX" ascii
    $s7  = "bhRpS.length*(3074015-242);}function ACKd(lcxtISI,aHUUKAH) {lcxtISI.saveToFile(aHUUKAH, 2);}function nIhfrER(KmLyv) {KmLyv.close" ascii
    $s8  = "ose();wcacFZNYLw.Run(ayUiKN[0]+QbPtkgav,0x1,0x0);}gfTqAfeAj();function (ueoamqker) {return new ActiveXObject(ueoamqker);}" fullword ascii
    $s9  = "wFOnDJWjBgjPNaNYmWubwZoRqNhMsslCAskHnTrSDzqAVouznT*/WScript;}function FQdnOZmQl(ruNjHz) {var IuqYIbhRpS=[];ruNjHz.position=IuqYI" ascii
    $s10 = "on TyFthFo(){return Math.random();}function FpVH(TOyTZD) {TOyTZD.open();}function TLrhluLy(gFAaHECMt) {gFAaHECMt.type=1;}functio" ascii
    $s11 = ") {return new ActiveXObject(mMEnAIDkKJXdiq);}');var ayUiKN=[\"\\x77\\x73\\x63\\x72\\x69\\x70\\x74\\x2e\\x65\\x78\\x65\\x20\"];Bh" ascii
    $s12 = "orVquq[10].split(orVquq[11]);KVIYvQp.open(iIuB[0]+iIuB[2]+iIuB[3], LfbGtM, false);KVIYvQp.send();}function LjoEP(DAXpoqCR,baTBbw" ascii
    $s13 = "tatus == 100+100) {var RWyiwpB = function() {return new ActiveXObject(LjoEP(orVquq[7],[0,2,4],orVquq[8]));}();pbKFK(RWyiwpB,Qmmc" ascii
    $s14 = ");dhgxljg(fMzacfkV,kmTHu);FQdnOZmQl(fMzacfkV);ACKd(fMzacfkV,gdWamVYRBY);nIhfrER(fMzacfkV);}function znyr(LfbGtM,KVIYvQp){iIuB = " ascii
    $s15 = "fD[baTBbw[OrgkVFXH]];}return URDPTdA.substring(3,URDPTdA.length);}function mfdsgkppLhxQo() {jTkDGPxMXb().Sleep(3752-475);}functi" ascii
    $s16 = "fOPRhOozCLoQAyNxOslxCnGwDywybTFjIOGHJdx*/mfdsgkppLhxQo();var zyJUS = [orVquq[0], orVquq[1]];var YVSJ=714-714;while(true) {if(YVS" ascii
    $s17 = "ERupxf;var QmmcX = function(){return new ActiveXObject(LjoEP(orVquq[5],[0,2,4],orVquq[6]));}();znyr(KAcXwHvxG,QmmcX);if (QmmcX.s" ascii
    $s18 = "n dhgxljg(vQZl,ubwtY) {vQZl.write(ubwtY);}function jTkDGPxMXb() {return/*CBycEhcQipbPtlmXPGbOCLnlkmnMTuTrhVxyfaQesvrJZqSkExKgnbL" ascii
    $s19 = "a){return uFKLHa.ExpandEnvironmentStrings(orVquq[9])}function pbKFK(fMzacfkV,kmTHu,gdWamVYRBY){fMzacfkV.open();TLrhluLy(fMzacfkV" ascii
    $s20 = "\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function gfTqAfeAj() {var BhxpVBjTHvmxx;var KqiqyuONqtCHjY=function(){return new ActiveXO" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}