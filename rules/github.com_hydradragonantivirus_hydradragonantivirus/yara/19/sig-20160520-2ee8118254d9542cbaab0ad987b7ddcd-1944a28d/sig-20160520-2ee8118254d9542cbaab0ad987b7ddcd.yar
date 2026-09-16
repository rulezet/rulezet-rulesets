rule sig_20160520_2ee8118254d9542cbaab0ad987b7ddcd {
  meta:
    description = "datamaliciousorder - file 20160520_2ee8118254d9542cbaab0ad987b7ddcd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "48084f1495e791c3b5f50cf64a5e2781489a2fbbe4f9751d2a672df401db7232"

  strings:
    $s1  = "function kldsbRzX(agXTn) {var qnfseOfu=FSjSpfCJsvfNIpNom[2];for(var KsTYS=0;KsTYS<agXTn;KsTYS++){rSjOC+=qnfseOfu.charAt(Math.flo" ascii
    $s2  = "function kldsbRzX(agXTn) {var qnfseOfu=FSjSpfCJsvfNIpNom[2];for(var KsTYS=0;KsTYS<agXTn;KsTYS++){rSjOC+=qnfseOfu.charAt(Math.flo" ascii
    $s3  = "try{RsoDobPDQ(KPkBK[Vunm], IgEjDmK() + FSjSpfCJsvfNIpNom[9], 1)}catch(e){}; " fullword ascii
    $s4  = "function RsoDobPDQ(JYjvXzNBV,EghiYHM,PTinuaaj){" fullword ascii
    $s5  = "function IgEjDmK() {var YyhG=100000;var uSWDqH = 100;return Math.random()*(YyhG-uSWDqH)+uSWDqH;}" fullword ascii
    $s6  = "or(Math.random()*qnfseOfu.length));}return rSjOC;}" fullword ascii
    $s7  = "function dFHO(HSoBxS,EZnWdno){WIYk = FSjSpfCJsvfNIpNom[11].split(FSjSpfCJsvfNIpNom[12]);EZnWdno.open(WIYk[0]+WIYk[2]+WIYk[3], HS" ascii
    $s8  = "function rirHtg(OHtQmR){return OHtQmR.ExpandEnvironmentStrings(FSjSpfCJsvfNIpNom[10])}" fullword ascii
    $s9  = "oBxS, false);EZnWdno.send();}" fullword ascii
    $s10 = "function dFHO(HSoBxS,EZnWdno){WIYk = FSjSpfCJsvfNIpNom[11].split(FSjSpfCJsvfNIpNom[12]);EZnWdno.open(WIYk[0]+WIYk[2]+WIYk[3], HS" ascii
    $s11 = "function brRIm(RHgFayVl,cibJKd,VfkaCclsv){DoLxF=RHgFayVl.split(VfkaCclsv);IfTHKer = FSjSpfCJsvfNIpNom[13];for(HbXxxpgh=0;HbXxxpg" ascii
    $s12 = "h<cibJKd.length;HbXxxpgh++) {IfTHKer+=DoLxF[cibJKd[HbXxxpgh]];}return IfTHKer.substring(3,IfTHKer.length);}" fullword ascii
    $s13 = "function bMmzy(OHtQmR){return new ActiveXObject(OHtQmR);}" fullword ascii
    $s14 = "function brRIm(RHgFayVl,cibJKd,VfkaCclsv){DoLxF=RHgFayVl.split(VfkaCclsv);IfTHKer = FSjSpfCJsvfNIpNom[13];for(HbXxxpgh=0;HbXxxpg" ascii
    $s15 = "function hIabZ(sYqdurJE,FeKor,IytwcFCmLj){sYqdurJE.open();sYqdurJE.type = 1;sYqdurJE.write(FeKor);sYqdurJE.position = 0;sYqdurJE" ascii
    $s16 = "function hIabZ(sYqdurJE,FeKor,IytwcFCmLj){sYqdurJE.open();sYqdurJE.type = 1;sYqdurJE.write(FeKor);sYqdurJE.position = 0;sYqdurJE" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}