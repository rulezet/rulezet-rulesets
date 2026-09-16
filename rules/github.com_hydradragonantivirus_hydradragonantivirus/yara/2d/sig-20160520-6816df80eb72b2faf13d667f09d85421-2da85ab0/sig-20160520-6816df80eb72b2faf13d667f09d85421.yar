rule sig_20160520_6816df80eb72b2faf13d667f09d85421 {
  meta:
    description = "datamaliciousorder - file 20160520_6816df80eb72b2faf13d667f09d85421.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "164e9d14722c872f442dc1072719ecc6768a7525dd80400006480529860db12d"

  strings:
    $s1  = "function xdfUsHIn(ieAzD) {var MhHPwCsE=IQjzT[2];for(var BhJgT=0;BhJgT<ieAzD;BhJgT++){WmiPt+=MhHPwCsE.charAt(Math.floor(Math.rand" ascii
    $s2  = "function xdfUsHIn(ieAzD) {var MhHPwCsE=IQjzT[2];for(var BhJgT=0;BhJgT<ieAzD;BhJgT++){WmiPt+=MhHPwCsE.charAt(Math.floor(Math.rand" ascii
    $s3  = "function lVYxQ(jaXspelw,XCKhto,seoDJrTpG){wEYtU=jaXspelw.split(seoDJrTpG);iSzHdTE = IQjzT[13];for(zUPIIDVM=0;zUPIIDVM<XCKhto.len" ascii
    $s4  = "function mtFb(TAQRwV,HigwaEJ){vvlp = IQjzT[11].split(IQjzT[12]);HigwaEJ.open(vvlp[0]+vvlp[2]+vvlp[3], TAQRwV, false);HigwaEJ.sen" ascii
    $s5  = "function APchBsE() {var hwVH=100000;var DQkAUO = 100;return Math.random()*(hwVH-DQkAUO)+DQkAUO;}" fullword ascii
    $s6  = "function jjmEA(bxzlnyMb,jNwjI,piscDbQiAG){bxzlnyMb.open();bxzlnyMb.type = 1;bxzlnyMb.write(jNwjI);bxzlnyMb.position = 0;bxzlnyMb" ascii
    $s7  = "gth;zUPIIDVM++) {iSzHdTE+=wEYtU[XCKhto[zUPIIDVM]];}return iSzHdTE.substring(3,iSzHdTE.length);}" fullword ascii
    $s8  = "function HeTSpB(nrYbWb){return nrYbWb.ExpandEnvironmentStrings(IQjzT[10])}" fullword ascii
    $s9  = "function jjxOn(nrYbWb){return new ActiveXObject(nrYbWb);}" fullword ascii
    $s10 = "function jjmEA(bxzlnyMb,jNwjI,piscDbQiAG){bxzlnyMb.open();bxzlnyMb.type = 1;bxzlnyMb.write(jNwjI);bxzlnyMb.position = 0;bxzlnyMb" ascii
    $s11 = "function lVYxQ(jaXspelw,XCKhto,seoDJrTpG){wEYtU=jaXspelw.split(seoDJrTpG);iSzHdTE = IQjzT[13];for(zUPIIDVM=0;zUPIIDVM<XCKhto.len" ascii
    $s12 = "function mtFb(TAQRwV,HigwaEJ){vvlp = IQjzT[11].split(IQjzT[12]);HigwaEJ.open(vvlp[0]+vvlp[2]+vvlp[3], TAQRwV, false);HigwaEJ.sen" ascii
    $s13 = "if (XKDjJkQ==0) break;" fullword ascii
    $s14 = "try{XKDjJkQ=VbnFKQaQe(enchG[KyBg], APchBsE() + IQjzT[9], 1)}catch(e){}; " fullword ascii
    $s15 = "om()*MhHPwCsE.length));}return WmiPt;}" fullword ascii
    $s16 = "function VbnFKQaQe(CKSbplzjb,ZxLRkFH,pDovAspZ){" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}