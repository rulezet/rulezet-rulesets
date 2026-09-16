rule sig_20160523_5fc6545ee76c0e320961aba818bd87ee {
  meta:
    description = "datamaliciousorder - file 20160523_5fc6545ee76c0e320961aba818bd87ee.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "efef2f9446f8e88cd8518b8f192445b02834523ff6b67ecf011e4d04f56171f1"

  strings:
    $s1  = "function xDaOuQaNWZ(MDemaGom,WIXAoWRTeuFg) {MDemaGom.Run(WIXAoWRTeuFg, 0x1, 0x0);}" fullword ascii
    $s2  = "function MNOgcejWOR() {return/*WyQRsvIDMCvLryUHwQWOeWRqlXIFFHylIGsxrlgWjfFkNryfHvwIbMKjhgRINSCPOMHRcWQOMKtQtaINuilmVrrzxiorPuNFw" ascii
    $s3  = "function oIuetytE(nyrZu) {var zziZgfEv=ESUXhgEXeOYIqSriqvXTvGmY[13];for(var qEdHt=0;qEdHt<nyrZu;qEdHt++){JlDcz+=zziZgfEv.charAt(" ascii
    $s4  = "function oIuetytE(nyrZu) {var zziZgfEv=ESUXhgEXeOYIqSriqvXTvGmY[13];for(var qEdHt=0;qEdHt<nyrZu;qEdHt++){JlDcz+=zziZgfEv.charAt(" ascii
    $s5  = "Math.floor(Math.random()*zziZgfEv.length));}return JlDcz;}" fullword ascii
    $s6  = "function GPhB(CXjgRj) {CXjgRj.open();}" fullword ascii
    $s7  = "function pEDRN(svFYoJlA,YpMOgR,KCEIKCotC){fmWzw=svFYoJlA.split(KCEIKCotC);RxbNPDt = ESUXhgEXeOYIqSriqvXTvGmY[12];for(ZhVJyfOS=0;" ascii
    $s8  = "function jNIkR(CHViCN){return new ActiveXObject(CHViCN);}" fullword ascii
    $s9  = "ZhVJyfOS<YpMOgR.length;ZhVJyfOS++) {RxbNPDt+=fmWzw[YpMOgR[ZhVJyfOS]];}return RxbNPDt.substring(3,RxbNPDt.length);}" fullword ascii
    $s10 = "function zzYmBdv() {var uete=100000;var RzFBgk = 100;return YddaAmm()*(uete-RzFBgk)+RzFBgk;}" fullword ascii
    $s11 = "function GRwgT(RAbcSlpO,jQFgH,mopAjeQzRo){GPhB(RAbcSlpO);Wnoyfllw(RAbcSlpO);GttqhFg(RAbcSlpO,jQFgH);JPIThZKrm(RAbcSlpO);tVil(RAb" ascii
    $s12 = "function Wnoyfllw(kXbMuXHeH) {kXbMuXHeH.type=1;}" fullword ascii
    $s13 = "function JPIThZKrm(HmbtdK) {var BOAphkXTsD=[];HmbtdK.position=BOAphkXTsD.length*(4272561-540);}" fullword ascii
    $s14 = "2]+eqXJ[3], VWQVoW, false);dPfwlyJ.send();}" fullword ascii
    $s15 = "if(zEPJ>cwvxv.length) break;" fullword ascii
    $s16 = "function XUMg(VWQVoW,dPfwlyJ){eqXJ = ESUXhgEXeOYIqSriqvXTvGmY[10].split(ESUXhgEXeOYIqSriqvXTvGmY[11]);dPfwlyJ.open(eqXJ[0]+eqXJ[" ascii
    $s17 = "function XUMg(VWQVoW,dPfwlyJ){eqXJ = ESUXhgEXeOYIqSriqvXTvGmY[10].split(ESUXhgEXeOYIqSriqvXTvGmY[11]);dPfwlyJ.open(eqXJ[0]+eqXJ[" ascii
    $s18 = "function qXXbJy(CHViCN){return CHViCN.ExpandEnvironmentStrings(ESUXhgEXeOYIqSriqvXTvGmY[9])}" fullword ascii
    $s19 = "function MNOgcejWOR() {return/*WyQRsvIDMCvLryUHwQWOeWRqlXIFFHylIGsxrlgWjfFkNryfHvwIbMKjhgRINSCPOMHRcWQOMKtQtaINuilmVrrzxiorPuNFw" ascii
    $s20 = "function EqVpprkebNxqq() {MNOgcejWOR().Sleep(2319103-754);}" fullword ascii

  condition:
    uint16(0) == 0x1b27 and
    8 of them
}