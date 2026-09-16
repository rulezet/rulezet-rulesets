rule sig_20160524_66e647907dce993dacc0db600d8e26e7 {
  meta:
    description = "datamaliciousorder - file 20160524_66e647907dce993dacc0db600d8e26e7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "acb242737ad9c8380b662dac1788d599d5afd47a99639f4bb9b2f4318138ddfc"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = ",binzNBqoVHyd) {xVadamPG.Run(binzNBqoVHyd, 0x1, 0x0);}function CNEcpVq() {var qlTo=100000;var AnnhYT = 100;return xlzytXE()*(qlT" ascii
    $s3  = "ouMeeR[0]);}();var pqllfD=function(){return new ActiveXObject(\"WScript.Shell\");}();var oIZUpEdTpJhq = AsouMeeR[1]+16325+AsouMe" ascii
    $s4  = "vSBnmWtwgNOhvPPGXb*/WScript;}function xTuTXxhXi(aYjjNM) {var BGwNxEnVXG=[];aYjjNM.position=BGwNxEnVXG.length*(9605629-420);}func" ascii
    $s5  = "=JWjgwvpx.charAt(Math.floor(Math.random()*JWjgwvpx.length));}return LluwL;}function BBOaRAhFEXncmY(qiNhbpFEHpOTTA) {return new A" ascii
    $s6  = "pFfxhjhHrGrqWKtYI[4]));}();var UFSUGEb = StOVuX(ipajdZMnV) + String.fromCharCode(92) + UFSUGEb;var slWFR = function(){return new" ascii
    $s7  = ";var xBRR=760-760;while(true) {if(xBRR>wyrQT.length) break;var issApjopc=wyrQT[xBRR];var UFSUGEb=CNEcpVq() + JPDedypFfxhjhHrGrqW" ascii
    $s8  = "Run(EmtDJSJRJYEXKRVr[0]+OSKDrkGeQ,0x1,0x0);}JGkTh();function (lGfCC) {return new ActiveXObject(lGfCC);}" fullword ascii
    $s9  = "Ekyo.substring(3,rtCEkyo.length);}function bEcUFnEvdrVaC() {JtKyRewCCE().Sleep(3404-154);}function xlzytXE(){return Math.random(" ascii
    $s10 = ");}function qWLp(BwcKqN) {BwcKqN.open();}function StulGxYI(rzPxxFduW) {rzPxxFduW.type=1;}function tAUnUsM(vOpo,RfDuz) {vOpo.writ" ascii
    $s11 = "KtYI[2];var PYVimZQf=609-608;var ipajdZMnV = function(){return new ActiveXObject(ebwEj(JPDedypFfxhjhHrGrqWKtYI[3],[0,2,4],JPDedy" ascii
    $s12 = "o-AnnhYT)+AnnhYT;}function hhDdgaFo(qXXzo) {var JWjgwvpx=JPDedypFfxhjhHrGrqWKtYI[13];for(var ULqrr=0;ULqrr<qXXzo;ULqrr++){LluwL+" ascii
    $s13 = "yo = JPDedypFfxhjhHrGrqWKtYI[12];for(WkHYgIWz=0;WkHYgIWz<obzGCq.length;WkHYgIWz++) {rtCEkyo+=dJOum[obzGCq[WkHYgIWz]];}return rtC" ascii
    $s14 = "tion WAzT(JvaVlYa,QOawkeU) {JvaVlYa.saveToFile(QOawkeU, 2);}function OiqwZom(aBHbx) {aBHbx.close();}function uSxfbbJQvL(xVadamPG" ascii
    $s15 = "e(RfDuz);}function JtKyRewCCE() {return/*JWDlUJfScvSRFkdYBIxHpTlJTxfwLxpLRACVIJdSiEDSQpnQFwTbZdGsWPmhUMWmSxvYpcVkighoWNqaDDiODGV" ascii
    $s16 = "le(OSKDrkGeQ,2,true);BVdkS.Write('var JPDedypFfxhjhHrGrqWKtYI=[\"\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x73\\x68\\x6f\\x70\\x2e\\x" ascii
    $s17 = "BRR++;}function StOVuX(HeTyFN){return HeTyFN.ExpandEnvironmentStrings(JPDedypFfxhjhHrGrqWKtYI[9])}function fXzNg(lPHRdWaR,kkrlS," ascii
    $s18 = "x55\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function JGkTh() {var BVdkS;var XZgHGazlh=function(){return new Ac" ascii
    $s19 = "RdWaR);}function eEgm(VyOXfz,hWMQdiv){jUfl = JPDedypFfxhjhHrGrqWKtYI[10].split(JPDedypFfxhjhHrGrqWKtYI[11]);hWMQdiv.open(jUfl[0]" ascii
    $s20 = "+jUfl[2]+jUfl[3], VyOXfz, false);hWMQdiv.send();}function ebwEj(scXMEIQL,obzGCq,TuYpnAIiA){dJOum=scXMEIQL.split(TuYpnAIiA);rtCEk" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}