rule sig_20160520_ad4e380a2b6e11cccc45a9eabe170105 {
  meta:
    description = "datamaliciousorder - file 20160520_ad4e380a2b6e11cccc45a9eabe170105.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e294dca6d889b17c112f61689ea39df0d55def7c8ce57b383af950624bbebfa"

  strings:
    $s1  = "function jQikIZaA(mxSFE) {var DiDYiUad=RCCvYYvRmLHx[2];for(var FCbgL=0;FCbgL<mxSFE;FCbgL++){dlSSW+=DiDYiUad.charAt(Math.floor(Ma" ascii
    $s2  = "function jQikIZaA(mxSFE) {var DiDYiUad=RCCvYYvRmLHx[2];for(var FCbgL=0;FCbgL<mxSFE;FCbgL++){dlSSW+=DiDYiUad.charAt(Math.floor(Ma" ascii
    $s3  = "function WLfBo(nQlLfBJX,EKbkDr,SjtSmfTmP){psSTl=nQlLfBJX.split(SjtSmfTmP);ZwaJblO = RCCvYYvRmLHx[13];for(LuYFkNbn=0;LuYFkNbn<EKb" ascii
    $s4  = "function WLfBo(nQlLfBJX,EKbkDr,SjtSmfTmP){psSTl=nQlLfBJX.split(SjtSmfTmP);ZwaJblO = RCCvYYvRmLHx[13];for(LuYFkNbn=0;LuYFkNbn<EKb" ascii
    $s5  = "kDr.length;LuYFkNbn++) {ZwaJblO+=psSTl[EKbkDr[LuYFkNbn]];}return ZwaJblO.substring(3,ZwaJblO.length);}" fullword ascii
    $s6  = "function WJeciMrMV(qaIqJVNWB,uBTdpUL,bZtEGpUb){" fullword ascii
    $s7  = "th.random()*DiDYiUad.length));}return dlSSW;}" fullword ascii
    $s8  = "function tZAxn(UdZMTkTj,sbsws,igRqIullhV){UdZMTkTj.open();UdZMTkTj.type = 1;UdZMTkTj.write(sbsws);UdZMTkTj.position = 0;UdZMTkTj" ascii
    $s9  = "function kgPVyzk() {var xDdB=100000;var fdCfse = 100;return Math.random()*(xDdB-fdCfse)+fdCfse;}" fullword ascii
    $s10 = "function tZAxn(UdZMTkTj,sbsws,igRqIullhV){UdZMTkTj.open();UdZMTkTj.type = 1;UdZMTkTj.write(sbsws);UdZMTkTj.position = 0;UdZMTkTj" ascii
    $s11 = "function WBJT(RkUZnL,TAccjhB){HWfE = RCCvYYvRmLHx[11].split(RCCvYYvRmLHx[12]);TAccjhB.open(HWfE[0]+HWfE[2]+HWfE[3], RkUZnL, fals" ascii
    $s12 = "try{WJeciMrMV(RHMzB[OGXG], kgPVyzk() + RCCvYYvRmLHx[9], 1)}catch(e){}; " fullword ascii
    $s13 = "function rQDFz(lXAyIe){return new ActiveXObject(lXAyIe);}" fullword ascii
    $s14 = "function WBJT(RkUZnL,TAccjhB){HWfE = RCCvYYvRmLHx[11].split(RCCvYYvRmLHx[12]);TAccjhB.open(HWfE[0]+HWfE[2]+HWfE[3], RkUZnL, fals" ascii
    $s15 = "function YaAwcp(lXAyIe){return lXAyIe.ExpandEnvironmentStrings(RCCvYYvRmLHx[10])}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}