rule sig_20160520_d95bc3cc3400f20f290cdfb19b1c0489 {
  meta:
    description = "datamaliciousorder - file 20160520_d95bc3cc3400f20f290cdfb19b1c0489.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02561b1a57abd50c23434932cb2f842aef285181017b61c553e47f3efe0431c9"

  strings:
    $s1  = "function vSlpZDoG(KfCUC) {var cLvZzbdZ=VEAUIS[2];for(var clibO=0;clibO<KfCUC;clibO++){yDcqA+=cLvZzbdZ.charAt(Math.floor(Math.ran" ascii
    $s2  = "function vSlpZDoG(KfCUC) {var cLvZzbdZ=VEAUIS[2];for(var clibO=0;clibO<KfCUC;clibO++){yDcqA+=cLvZzbdZ.charAt(Math.floor(Math.ran" ascii
    $s3  = "function DTbU(KQalPM,kToLSKh){tIdS = VEAUIS[11].split(VEAUIS[12]);kToLSKh.open(tIdS[0]+tIdS[2]+tIdS[3], KQalPM, false);kToLSKh.s" ascii
    $s4  = "function vaqBc(MGEXcxOX,VtRwQz,XlLuTHfjQ){Mkntk=MGEXcxOX.split(XlLuTHfjQ);gADAsFr = VEAUIS[13];for(DUxyqFoe=0;DUxyqFoe<VtRwQz.le" ascii
    $s5  = "function iyFsCpdfF(FvnLNDWyY,xhMDCYO,uRbqQOuC){" fullword ascii
    $s6  = "function WxIfi(FYxweB){return new ActiveXObject(FYxweB);}" fullword ascii
    $s7  = "function rKvfc(xTLwAbNw,yGDBx,RZJcwttqED){xTLwAbNw.open();xTLwAbNw.type = 1;xTLwAbNw.write(yGDBx);xTLwAbNw.position = 0;xTLwAbNw" ascii
    $s8  = "function CPPgUwj() {var DXsa=100000;var rCBShd = 100;return Math.random()*(DXsa-rCBShd)+rCBShd;}" fullword ascii
    $s9  = "function DTbU(KQalPM,kToLSKh){tIdS = VEAUIS[11].split(VEAUIS[12]);kToLSKh.open(tIdS[0]+tIdS[2]+tIdS[3], KQalPM, false);kToLSKh.s" ascii
    $s10 = "ngth;DUxyqFoe++) {gADAsFr+=Mkntk[VtRwQz[DUxyqFoe]];}return gADAsFr.substring(3,gADAsFr.length);}" fullword ascii
    $s11 = "function rKvfc(xTLwAbNw,yGDBx,RZJcwttqED){xTLwAbNw.open();xTLwAbNw.type = 1;xTLwAbNw.write(yGDBx);xTLwAbNw.position = 0;xTLwAbNw" ascii
    $s12 = "function JDUWBU(FYxweB){return FYxweB.ExpandEnvironmentStrings(VEAUIS[10])}" fullword ascii
    $s13 = "function vaqBc(MGEXcxOX,VtRwQz,XlLuTHfjQ){Mkntk=MGEXcxOX.split(XlLuTHfjQ);gADAsFr = VEAUIS[13];for(DUxyqFoe=0;DUxyqFoe<VtRwQz.le" ascii
    $s14 = "try{aJAIdCQ=iyFsCpdfF(SDYOP[sjBv], CPPgUwj() + VEAUIS[9], 1)}catch(e){}; " fullword ascii
    $s15 = "if (aJAIdCQ==0) break;" fullword ascii
    $s16 = "dom()*cLvZzbdZ.length));}return yDcqA;}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}