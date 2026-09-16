rule sig_20160520_6735435e57637c93ad39cefa1ae217a0 {
  meta:
    description = "datamaliciousorder - file 20160520_6735435e57637c93ad39cefa1ae217a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "545e6c939f746917e22f005e428447896da9c14a91b5309dd193c751ae51ed24"

  strings:
    $s1  = "function MaOiRtuv(lUZcg) {var vAHnnwqR=oezZocGysVpJqagmsUD[2];for(var oMIFQ=0;oMIFQ<lUZcg;oMIFQ++){TMMMR+=vAHnnwqR.charAt(Math.f" ascii
    $s2  = "function MaOiRtuv(lUZcg) {var vAHnnwqR=oezZocGysVpJqagmsUD[2];for(var oMIFQ=0;oMIFQ<lUZcg;oMIFQ++){TMMMR+=vAHnnwqR.charAt(Math.f" ascii
    $s3  = "function xLGkx(TvzmIHHc,YroEe,VzeUtSnLiy){TvzmIHHc.open();TvzmIHHc.type = 1;TvzmIHHc.write(YroEe);TvzmIHHc.position = 0;TvzmIHHc" ascii
    $s4  = "try{euGQXpI=dEBCZkEMc(fwbPn[wqSU], SwFeFBQ() + oezZocGysVpJqagmsUD[9], 1)}catch(e){}; " fullword ascii
    $s5  = "function xLGkx(TvzmIHHc,YroEe,VzeUtSnLiy){TvzmIHHc.open();TvzmIHHc.type = 1;TvzmIHHc.write(YroEe);TvzmIHHc.position = 0;TvzmIHHc" ascii
    $s6  = "function SwFeFBQ() {var BocQ=100000;var dWlwIk = 100;return Math.random()*(BocQ-dWlwIk)+dWlwIk;}" fullword ascii
    $s7  = ", Xqisxn, false);PpyFIUo.send();}" fullword ascii
    $s8  = "loor(Math.random()*vAHnnwqR.length));}return TMMMR;}" fullword ascii
    $s9  = "function dEBCZkEMc(vbfQvbkDW,hvUChdl,skcDWdIt){" fullword ascii
    $s10 = "function pvoW(Xqisxn,PpyFIUo){kKKC = oezZocGysVpJqagmsUD[11].split(oezZocGysVpJqagmsUD[12]);PpyFIUo.open(kKKC[0]+kKKC[2]+kKKC[3]" ascii
    $s11 = "if (euGQXpI==0) break;" fullword ascii
    $s12 = "DGp<RwVmys.length;OdjleDGp++) {ddYGbna+=ArPcI[RwVmys[OdjleDGp]];}return ddYGbna.substring(3,ddYGbna.length);}" fullword ascii
    $s13 = "function bUfBO(KfRmAj){return new ActiveXObject(KfRmAj);}" fullword ascii
    $s14 = "function pvoW(Xqisxn,PpyFIUo){kKKC = oezZocGysVpJqagmsUD[11].split(oezZocGysVpJqagmsUD[12]);PpyFIUo.open(kKKC[0]+kKKC[2]+kKKC[3]" ascii
    $s15 = "function qABjVl(KfRmAj){return KfRmAj.ExpandEnvironmentStrings(oezZocGysVpJqagmsUD[10])}" fullword ascii
    $s16 = "function AEWCA(sQWztbMB,RwVmys,WKzGNBGGT){ArPcI=sQWztbMB.split(WKzGNBGGT);ddYGbna = oezZocGysVpJqagmsUD[13];for(OdjleDGp=0;Odjle" ascii
    $s17 = "function AEWCA(sQWztbMB,RwVmys,WKzGNBGGT){ArPcI=sQWztbMB.split(WKzGNBGGT);ddYGbna = oezZocGysVpJqagmsUD[13];for(OdjleDGp=0;Odjle" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}