rule sig_20160524_c0d2fa40ee345426b563620b74e763ee {
  meta:
    description = "datamaliciousorder - file 20160524_c0d2fa40ee345426b563620b74e763ee.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58010a52c19ac9302ae5602a9c110e895e3e8fa92d51df7afd23b2abfc3d5c9a"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "l;}function wcVAAeoT(bpaUL) {var bEIPgZPZ=pVBIDsPGxynOl[13];for(var WIsAo=0;WIsAo<bpaUL;WIsAo++){DYdCk+=bEIPgZPZ.charAt(Math.flo" ascii
    $s3  = "UUFtbtOE=function(){return new ActiveXObject(\"WScript.Shell\");}();var AZVLvFQyEqRo = rvCdpzSqrqxN[1]+17183+rvCdpzSqrqxN[2];var" ascii
    $s4  = "ring.fromCharCode(92) + wfrEmub;var sQxHu = function(){return new ActiveXObject(ebwky(pVBIDsPGxynOl[5],[0,2,4],pVBIDsPGxynOl[6])" ascii
    $s5  = "{JtPQHwhD.Run(dBKtOFcZhioF, 0x1, 0x0);}function sOqpqle() {var TYnH=100000;var WUEsXl = 100;return OAPgUcz()*(TYnH-WUEsXl)+WUEsX" ascii
    $s6  = "euq*/WScript;}function YqSPUIkQi(ZdBagx) {var BhuOVPHcnJ=[];ZdBagx.position=BhuOVPHcnJ.length*(8868432-181);}function mMJa(aONBq" ascii
    $s7  = "= function(){return new ActiveXObject(ebwky(pVBIDsPGxynOl[3],[0,2,4],pVBIDsPGxynOl[4]));}();var wfrEmub = AQXOLZ(OwiSvzSYT) + St" ascii
    $s8  = "(EnAI>paJBo.length) break;var HGhqhHpev=paJBo[EnAI];var wfrEmub=sOqpqle() + pVBIDsPGxynOl[2];var lOBFvord=493-492;var OwiSvzSYT " ascii
    $s9  = "wVFpPCQeUonO,0x1,0x0);}dlFxjHAYFAc();function (YFvHdGECdTMlV) {return new ActiveXObject(YFvHdGECdTMlV);}" fullword ascii
    $s10 = "[2]+crqA[3], erFcpK, false);MSkzzEC.send();}function ebwky(ECHGCbVg,FkxdaW,ndwDNihWX){MAwRq=ECHGCbVg.split(ndwDNihWX);xkyZnwg = " ascii
    $s11 = "U(pVGnym) {pVGnym.open();}function tpJVtmMU(lNbIagsir) {lNbIagsir.type=1;}function bdUoKbQ(ySEt,YKDDt) {ySEt.write(YKDDt);}funct" ascii
    $s12 = "pVBIDsPGxynOl[12];for(aQupIKOO=0;aQupIKOO<FkxdaW.length;aQupIKOO++) {xkyZnwg+=MAwRq[FkxdaW[aQupIKOO]];}return xkyZnwg.substring(" ascii
    $s13 = "JF,vYtPvrs) {aONBqJF.saveToFile(vYtPvrs, 2);}function wMnEfge(CUNHi) {CUNHi.close();}function wtoXOkSTBX(JtPQHwhD,dBKtOFcZhioF) " ascii
    $s14 = "3,xkyZnwg.length);}function TKWDGFxEiixAL() {ZiYXJdmncR().Sleep(4332-929);}function OAPgUcz(){return Math.random();}function Pxc" ascii
    $s15 = ");}();sDgC(HGhqhHpev,sQxHu);if (sQxHu.status == 100+100) {var GMQeNLv = function() {return new ActiveXObject(ebwky(pVBIDsPGxynOl" ascii
    $s16 = "wmaaeqeUofMEYiJvFFimkaSujAaMC*/TKWDGFxEiixAL();var paJBo = [pVBIDsPGxynOl[0], pVBIDsPGxynOl[1]];var EnAI=695-695;while(true) {if" ascii
    $s17 = "Ro);wMnEfge(VNboVHet);}function sDgC(erFcpK,MSkzzEC){crqA = pVBIDsPGxynOl[10].split(pVBIDsPGxynOl[11]);MSkzzEC.open(crqA[0]+crqA" ascii
    $s18 = "x45\\x4d\\x50\\x25\"];function dlFxjHAYFAc() {var MAhGPo;var PZxkK=function(){return new ActiveXObject(rvCdpzSqrqxN[0]);}();var " ascii
    $s19 = "or(Math.random()*bEIPgZPZ.length));}return DYdCk;}function HqENCbQOPSMdzZ(mFljFTeGMQJcWV) {return new ActiveXObject(mFljFTeGMQJc" ascii
    $s20 = "ile(wVFpPCQeUonO,2,true);MAhGPo.Write('var pVBIDsPGxynOl=[\"\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x73\\x68\\x6f\\x70\\x2e\\x64\\x" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}