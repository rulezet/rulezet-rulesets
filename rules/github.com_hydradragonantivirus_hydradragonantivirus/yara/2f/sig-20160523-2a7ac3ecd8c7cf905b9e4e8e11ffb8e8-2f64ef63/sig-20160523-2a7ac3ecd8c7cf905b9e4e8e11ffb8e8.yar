rule sig_20160523_2a7ac3ecd8c7cf905b9e4e8e11ffb8e8 {
  meta:
    description = "datamaliciousorder - file 20160523_2a7ac3ecd8c7cf905b9e4e8e11ffb8e8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e2f135cb2644749c00c79cb96ce2b4534f62998203a20ec08cc5069bf37816cb"

  strings:
    $s1  = "function BZriGkAk(KNIXP) {var JICNgwyJ=tjBJdanrGWdPrCNg[13];for(var KfVcC=0;KfVcC<KNIXP;KfVcC++){YnfSg+=JICNgwyJ.charAt(Math.flo" ascii
    $s2  = "function kjwqTHmIvA(EvXpYyTS,WooEmsHYMNvx) {EvXpYyTS.Run(WooEmsHYMNvx, 0x1, 0x0);}" fullword ascii
    $s3  = "function qxvhFovdMN() {return/*BzZsakDnAinvywrgoOvAlPEnUdAsRnYIfvyuTBhjsMUYoXclxxfLotcHWtcYguCSZeRrnCnRaeNzoFiAQoaUsjadxCfPwnxEG" ascii
    $s4  = "function BZriGkAk(KNIXP) {var JICNgwyJ=tjBJdanrGWdPrCNg[13];for(var KfVcC=0;KfVcC<KNIXP;KfVcC++){YnfSg+=JICNgwyJ.charAt(Math.flo" ascii
    $s5  = "function sQBIpoi(){return Math.random();}" fullword ascii
    $s6  = "cE, false);tTqhuew.send();}" fullword ascii
    $s7  = "function HHQkwUGJHrPsN() {qxvhFovdMN().Sleep(2410576-102);}" fullword ascii
    $s8  = "function qIcMl(cpkEzeML,zILKa,rSMEybdANP){nGwh(cpkEzeML);KyAFpVAq(cpkEzeML);JNCvTlT(cpkEzeML,zILKa);mtJtCzfhA(cpkEzeML);Wsrn(cpk" ascii
    $s9  = "function seKQ(OiowcE,tTqhuew){zBOo = tjBJdanrGWdPrCNg[10].split(tjBJdanrGWdPrCNg[11]);tTqhuew.open(zBOo[0]+zBOo[2]+zBOo[3], Oiow" ascii
    $s10 = "function mxtPEJK(noTvD) {noTvD.close();}" fullword ascii
    $s11 = "function JEnGrLc() {var fRbp=100000;var NNDqYz = 100;return sQBIpoi()*(fRbp-NNDqYz)+NNDqYz;}" fullword ascii
    $s12 = "function JhPbF(ktrqErvS,ljfEBJ,xraVmYKmz){AJFYV=ktrqErvS.split(xraVmYKmz);gppxKHH = tjBJdanrGWdPrCNg[12];for(OoInFCjZ=0;OoInFCjZ" ascii
    $s13 = "or(Math.random()*JICNgwyJ.length));}return YnfSg;}" fullword ascii
    $s14 = "function JNCvTlT(SBYA,gOjRJ) {SBYA.write(gOjRJ);}" fullword ascii
    $s15 = "function seKQ(OiowcE,tTqhuew){zBOo = tjBJdanrGWdPrCNg[10].split(tjBJdanrGWdPrCNg[11]);tTqhuew.open(zBOo[0]+zBOo[2]+zBOo[3], Oiow" ascii
    $s16 = "function nGwh(qmIExd) {qmIExd.open();}" fullword ascii
    $s17 = "function qxvhFovdMN() {return/*BzZsakDnAinvywrgoOvAlPEnUdAsRnYIfvyuTBhjsMUYoXclxxfLotcHWtcYguCSZeRrnCnRaeNzoFiAQoaUsjadxCfPwnxEG" ascii
    $s18 = "function Wsrn(qIHJtXk,hkeBwXo) {qIHJtXk.saveToFile(hkeBwXo, 2);}" fullword ascii
    $s19 = "function mtJtCzfhA(kweFNj) {var NJUethuMJO=[];kweFNj.position=NJUethuMJO.length*(460366-859);}" fullword ascii
    $s20 = "if(OZpi>TUDnb.length) break;" fullword ascii

  condition:
    uint16(0) == 0x1b27 and
    8 of them
}