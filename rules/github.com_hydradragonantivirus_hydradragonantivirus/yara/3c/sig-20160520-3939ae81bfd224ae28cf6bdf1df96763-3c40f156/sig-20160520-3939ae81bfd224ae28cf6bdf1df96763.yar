rule sig_20160520_3939ae81bfd224ae28cf6bdf1df96763 {
  meta:
    description = "datamaliciousorder - file 20160520_3939ae81bfd224ae28cf6bdf1df96763.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de883ef7f85bd2ccb952f95388bfd137d0f3e444d8e2f4c455c611fa10e4e38c"

  strings:
    $s1  = "function vPPlmmCo(XSXsZ) {var Mnpsxixz=GSsyeVwezYqK[2];for(var gUHtq=0;gUHtq<XSXsZ;gUHtq++){jnzil+=Mnpsxixz.charAt(Math.floor(Ma" ascii
    $s2  = "function vPPlmmCo(XSXsZ) {var Mnpsxixz=GSsyeVwezYqK[2];for(var gUHtq=0;gUHtq<XSXsZ;gUHtq++){jnzil+=Mnpsxixz.charAt(Math.floor(Ma" ascii
    $s3  = "pdv.length;obPYAyxz++) {EuiKLsn+=AZgHg[pRupdv[obPYAyxz]];}return EuiKLsn.substring(3,EuiKLsn.length);}" fullword ascii
    $s4  = "try{XiVlIdC=ALEYsoTGZ(ifWJy[utKy], NWlHSXY() + GSsyeVwezYqK[9], 1)}catch(e){}; " fullword ascii
    $s5  = "function wtIdm(yHoJGl){return new ActiveXObject(yHoJGl);}" fullword ascii
    $s6  = "function UAVu(sEReXz,YLIQbGZ){HlHS = GSsyeVwezYqK[11].split(GSsyeVwezYqK[12]);YLIQbGZ.open(HlHS[0]+HlHS[2]+HlHS[3], sEReXz, fals" ascii
    $s7  = "function ALEYsoTGZ(vVHOvIBoD,tOqKaaE,jdppQzni){" fullword ascii
    $s8  = "th.random()*Mnpsxixz.length));}return jnzil;}" fullword ascii
    $s9  = "function MVHDl(VoueCfNP,XqypK,GVfVnUhhXN){VoueCfNP.open();VoueCfNP.type = 1;VoueCfNP.write(XqypK);VoueCfNP.position = 0;VoueCfNP" ascii
    $s10 = "function UAVu(sEReXz,YLIQbGZ){HlHS = GSsyeVwezYqK[11].split(GSsyeVwezYqK[12]);YLIQbGZ.open(HlHS[0]+HlHS[2]+HlHS[3], sEReXz, fals" ascii
    $s11 = "if (XiVlIdC==0) break;" fullword ascii
    $s12 = "function wgxQT(cKZkoPOL,pRupdv,CocGyzkcT){AZgHg=cKZkoPOL.split(CocGyzkcT);EuiKLsn = GSsyeVwezYqK[13];for(obPYAyxz=0;obPYAyxz<pRu" ascii
    $s13 = "function MVHDl(VoueCfNP,XqypK,GVfVnUhhXN){VoueCfNP.open();VoueCfNP.type = 1;VoueCfNP.write(XqypK);VoueCfNP.position = 0;VoueCfNP" ascii
    $s14 = "function wgxQT(cKZkoPOL,pRupdv,CocGyzkcT){AZgHg=cKZkoPOL.split(CocGyzkcT);EuiKLsn = GSsyeVwezYqK[13];for(obPYAyxz=0;obPYAyxz<pRu" ascii
    $s15 = "function SdqAbm(yHoJGl){return yHoJGl.ExpandEnvironmentStrings(GSsyeVwezYqK[10])}" fullword ascii
    $s16 = "function NWlHSXY() {var UnZz=100000;var XqyVaS = 100;return Math.random()*(UnZz-XqyVaS)+XqyVaS;}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}