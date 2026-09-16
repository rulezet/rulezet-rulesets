rule sig_20160523_d107c12a0ef80265267dec93be77f582 {
  meta:
    description = "datamaliciousorder - file 20160523_d107c12a0ef80265267dec93be77f582.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3424fa2e4684694667b733ccd0e8e1f137be5c4b1ba8d13d73b080e5946f1f98"

  strings:
    $s1  = "function IvoTEtpWBY(ngpOVNQk,UheYHUZBCzqB) {ngpOVNQk.Run(UheYHUZBCzqB, 0x1, 0x0);}" fullword ascii
    $s2  = "function OrijeTkeCb() {return/*VwrFdGtRWWlxlLPYldzqxjboSFaqjCcSxmOQjSyDmCCHZDUWMNYvVwXYgWBWENZkcbXXsAsRtrqGcNmamMQEzesjVweMJqUIl" ascii
    $s3  = "function fcenTnIr(ADSIl) {var cxopkuiu=pCBJQRVDLKWrkTvzX[13];for(var FgkdK=0;FgkdK<ADSIl;FgkdK++){lGjCg+=cxopkuiu.charAt(Math.fl" ascii
    $s4  = "function fcenTnIr(ADSIl) {var cxopkuiu=pCBJQRVDLKWrkTvzX[13];for(var FgkdK=0;FgkdK<ADSIl;FgkdK++){lGjCg+=cxopkuiu.charAt(Math.fl" ascii
    $s5  = "function ezxrZco(wQjMj) {wQjMj.close();}" fullword ascii
    $s6  = "if(ZKDU>sCUOM.length) break;" fullword ascii
    $s7  = "function JoeELxfLE(VjTeJH) {var RAHTzuWGLf=[];VjTeJH.position=RAHTzuWGLf.length*(9619557-460);}" fullword ascii
    $s8  = "function OrijeTkeCb() {return/*VwrFdGtRWWlxlLPYldzqxjboSFaqjCcSxmOQjSyDmCCHZDUWMNYvVwXYgWBWENZkcbXXsAsRtrqGcNmamMQEzesjVweMJqUIl" ascii
    $s9  = "function tOgSJcm(){return Math.random();}" fullword ascii
    $s10 = "function aExbs(fIoWGqoU,YWpOl,KbZaGZVIAd){UwZe(fIoWGqoU);EOjEYfkJ(fIoWGqoU);TDSXYLn(fIoWGqoU,YWpOl);JoeELxfLE(fIoWGqoU);YUwV(fIo" ascii
    $s11 = "t<iyCcSE.length;igFMQTjt++) {aipOlbz+=pZeWq[iyCcSE[igFMQTjt]];}return aipOlbz.substring(3,aipOlbz.length);}" fullword ascii
    $s12 = "function EVBkhHgelNYiy() {OrijeTkeCb().Sleep(2300715-331);}" fullword ascii
    $s13 = "function EOjEYfkJ(KqSlpckaP) {KqSlpckaP.type=1;}" fullword ascii
    $s14 = "function vYlvI(UiuIekZD,iyCcSE,xunlWKaIq){pZeWq=UiuIekZD.split(xunlWKaIq);aipOlbz = pCBJQRVDLKWrkTvzX[12];for(igFMQTjt=0;igFMQTj" ascii
    $s15 = "function wGEw(lPLmPp,jmNgRNZ){xxkx = pCBJQRVDLKWrkTvzX[10].split(pCBJQRVDLKWrkTvzX[11]);jmNgRNZ.open(xxkx[0]+xxkx[2]+xxkx[3], lP" ascii
    $s16 = "LmPp, false);jmNgRNZ.send();}" fullword ascii
    $s17 = "function MLPqG(mFUyqa){return new ActiveXObject(mFUyqa);}" fullword ascii
    $s18 = "function vYlvI(UiuIekZD,iyCcSE,xunlWKaIq){pZeWq=UiuIekZD.split(xunlWKaIq);aipOlbz = pCBJQRVDLKWrkTvzX[12];for(igFMQTjt=0;igFMQTj" ascii
    $s19 = "function UwZe(YDDrNR) {YDDrNR.open();}" fullword ascii
    $s20 = "function aExbs(fIoWGqoU,YWpOl,KbZaGZVIAd){UwZe(fIoWGqoU);EOjEYfkJ(fIoWGqoU);TDSXYLn(fIoWGqoU,YWpOl);JoeELxfLE(fIoWGqoU);YUwV(fIo" ascii

  condition:
    uint16(0) == 0x1d27 and
    8 of them
}