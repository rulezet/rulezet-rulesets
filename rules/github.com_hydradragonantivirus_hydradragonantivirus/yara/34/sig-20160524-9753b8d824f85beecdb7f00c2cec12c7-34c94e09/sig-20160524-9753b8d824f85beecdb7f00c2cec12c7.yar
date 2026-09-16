rule sig_20160524_9753b8d824f85beecdb7f00c2cec12c7 {
  meta:
    description = "datamaliciousorder - file 20160524_9753b8d824f85beecdb7f00c2cec12c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fdcac3ca08219010e5a77a444648e1cc37acd265502ac6e04e3d560b4d4155ac"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "yFqz=function(){return new ActiveXObject(BXyDghWaVVYPkCljXkG[0]);}();var iHLqGnNw=function(){return new ActiveXObject(\"WScript." ascii
    $s3  = "Ic[12];for(JIRcgfiJ=0;JIRcgfiJ<zoJBys.length;JIRcgfiJ++) {vEkjWGm+=gIrPh[zoJBys[JIRcgfiJ]];}return vEkjWGm.substring(3,vEkjWGm.l" ascii
    $s4  = "ue) {if(ETvO>QXZqx.length) break;var zSnlfUxui=QXZqx[ETvO];var utugymd=UALUqrw() + eeVGiBNjdcPZoBEhRgDdjIc[2];var XLOOglkr=551-5" ascii
    $s5  = ";var utugymd = truxmu(GDmfTSeWU) + String.fromCharCode(92) + utugymd;var JFQIi = function(){return new ActiveXObject(WwnAD(eeVGi" ascii
    $s6  = "oaPL[0]+XMGMcmdVVZhw,0x1,0x0);}UXEcqlDGZcLih();function (ywvqrmvKxmBGYT) {return new ActiveXObject(ywvqrmvKxmBGYT);}" fullword ascii
    $s7  = "rings(BXyDghWaVVYPkCljXkG[3])+String.fromCharCode(92)+ugUhekvbbQPem;sHcRyKl = REMLyFqz.OpenTextFile(XMGMcmdVVZhw,2,true);sHcRyKl" ascii
    $s8  = "HpjiXm.open();}function CUSuJDEE(DNTjJEVbY) {DNTjJEVbY.type=1;}function HwxVbIp(yqqW,gFFiS) {yqqW.write(gFFiS);}function lPLEDdl" ascii
    $s9  = "ength);}function baolQWjbdFWMU() {lPLEDdlhQj().Sleep(2928-537);}function PFmziwJ(){return Math.random();}function llhp(HpjiXm) {" ascii
    $s10 = "r(Math.random()*epJVYBYu.length));}return BJspz;}function wzWgecxyaIaLHu(RLYSHPwhHQbREe) {return new ActiveXObject(RLYSHPwhHQbRE" ascii
    $s11 = " {gybyAKu.saveToFile(ZkAZBXk, 2);}function qkYGqFY(hzRiE) {hzRiE.close();}function NxopHEBheR(HwCnRbay,QnXEQZqhCCEp) {HwCnRbay.R" ascii
    $s12 = ");CUSuJDEE(KBikdpel);HwxVbIp(KBikdpel,cnOkR);zmsfexsRX(KBikdpel);SWXv(KBikdpel,nmLjJUSprM);qkYGqFY(KBikdpel);}function mTDn(Vilt" ascii
    $s13 = "un(QnXEQZqhCCEp, 0x1, 0x0);}function UALUqrw() {var yLBH=100000;var cdJeXP = 100;return PFmziwJ()*(yLBH-cdJeXP)+cdJeXP;}function" ascii
    $s14 = "50;var GDmfTSeWU = function(){return new ActiveXObject(WwnAD(eeVGiBNjdcPZoBEhRgDdjIc[3],[0,2,4],eeVGiBNjdcPZoBEhRgDdjIc[4]));}()" ascii
    $s15 = "t;}function zmsfexsRX(YAClaH) {var kwnfnMYNJK=[];YAClaH.position=kwnfnMYNJK.length*(9133693-704);}function SWXv(gybyAKu,ZkAZBXk)" ascii
    $s16 = "skwoLCYzxDIlbsMq*/baolQWjbdFWMU();var QXZqx = [eeVGiBNjdcPZoBEhRgDdjIc[0], eeVGiBNjdcPZoBEhRgDdjIc[1]];var ETvO=996-996;while(tr" ascii
    $s17 = "false);IFglLUr.send();}function WwnAD(QKDzGyjH,zoJBys,WfjvnRLIA){gIrPh=QKDzGyjH.split(WfjvnRLIA);vEkjWGm = eeVGiBNjdcPZoBEhRgDdj" ascii
    $s18 = "5\\x71\\x77\\x4a\\x6e\\x54\\x58\\x74\\x68\\x7a\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function UXEcqlDGZcLih(" ascii
    $s19 = "QIi.ResponseBody,utugymd);}if (XLOOglkr > 0){try {NxopHEBheR(GDmfTSeWU,utugymd);} catch(e) {}break;};ETvO++;}function truxmu(zbi" ascii
    $s20 = "MCr){return zbiMCr.ExpandEnvironmentStrings(eeVGiBNjdcPZoBEhRgDdjIc[9])}function emHCa(KBikdpel,cnOkR,nmLjJUSprM){KBikdpel.open(" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}