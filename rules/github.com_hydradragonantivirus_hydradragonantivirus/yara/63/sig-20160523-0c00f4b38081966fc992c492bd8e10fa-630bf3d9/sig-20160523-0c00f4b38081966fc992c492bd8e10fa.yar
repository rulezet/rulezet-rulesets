rule sig_20160523_0c00f4b38081966fc992c492bd8e10fa {
  meta:
    description = "datamaliciousorder - file 20160523_0c00f4b38081966fc992c492bd8e10fa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd2f2b6b05ac4372d94e14867628b03d96fcb3d015309bcab784811709c1fe38"

  strings:
    $s1  = "function qvRlTzxXAP() {return/*tPXrcyscSAKjtgafFeXdmJmYlEZBETOcZhAhSPKPusAHIjVpRkvFFgQmwJnXazeJWaZTZaDoOybxASnqmUKYJYzkOPfLfZjLw" ascii
    $s2  = "function ZmOcPZpEVl(kwmQauSF,qJALjBTtDozM) {kwmQauSF.Run(qJALjBTtDozM, 0x1, 0x0);}" fullword ascii
    $s3  = "function xnqLZCkG(nJWSa) {var AwKvyWuI=KgRoGV[13];for(var djAeF=0;djAeF<nJWSa;djAeF++){PbITP+=AwKvyWuI.charAt(Math.floor(Math.ra" ascii
    $s4  = "function xnqLZCkG(nJWSa) {var AwKvyWuI=KgRoGV[13];for(var djAeF=0;djAeF<nJWSa;djAeF++){PbITP+=AwKvyWuI.charAt(Math.floor(Math.ra" ascii
    $s5  = "function FSuPxZb(Ryuw,lTidW) {Ryuw.write(lTidW);}" fullword ascii
    $s6  = "ndom()*AwKvyWuI.length));}return PbITP;}" fullword ascii
    $s7  = "function mHgAOE(WNDSSG){return WNDSSG.ExpandEnvironmentStrings(KgRoGV[9])}" fullword ascii
    $s8  = "function gmqYDccwV(cQvboP) {var ocDFbCIOuj=[];cQvboP.position=ocDFbCIOuj.length*(1133298-282);}" fullword ascii
    $s9  = "function MgXgpcg(){return Math.random();}" fullword ascii
    $s10 = "function Lgsqb(BtNKDgLu,CngNhF,yDwcetJxX){nlAgX=BtNKDgLu.split(yDwcetJxX);ojJlPbf = KgRoGV[12];for(bypsTDpP=0;bypsTDpP<CngNhF.le" ascii
    $s11 = "function BvTcYQR(tNMvl) {tNMvl.close();}" fullword ascii
    $s12 = "function lJmVyCor(AZayGSuCj) {AZayGSuCj.type=1;}" fullword ascii
    $s13 = "ngth;bypsTDpP++) {ojJlPbf+=nlAgX[CngNhF[bypsTDpP]];}return ojJlPbf.substring(3,ojJlPbf.length);}" fullword ascii
    $s14 = "function PTWd(NNdsUv,alEfADs){uNFG = KgRoGV[10].split(KgRoGV[11]);alEfADs.open(uNFG[0]+uNFG[2]+uNFG[3], NNdsUv, false);alEfADs.s" ascii
    $s15 = "function PTWd(NNdsUv,alEfADs){uNFG = KgRoGV[10].split(KgRoGV[11]);alEfADs.open(uNFG[0]+uNFG[2]+uNFG[3], NNdsUv, false);alEfADs.s" ascii
    $s16 = "function QBqF(ZJzHzHH,ZURgmrV) {ZJzHzHH.saveToFile(ZURgmrV, 2);}" fullword ascii
    $s17 = "function dQhAAjYDnRrfE() {qvRlTzxXAP().Sleep(2393135-218);}" fullword ascii
    $s18 = "function eHez(mwqmls) {mwqmls.open();}" fullword ascii
    $s19 = "function oXzze(WNDSSG){return new ActiveXObject(WNDSSG);}" fullword ascii
    $s20 = "function dyveZSO() {var nuZk=100000;var XYhldq = 100;return MgXgpcg()*(nuZk-XYhldq)+XYhldq;}" fullword ascii

  condition:
    uint16(0) == 0x0627 and
    8 of them
}