rule sig_20160520_36f98f8be360f938467d4c9b03b157d3 {
  meta:
    description = "datamaliciousorder - file 20160520_36f98f8be360f938467d4c9b03b157d3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e9480d27eeb87f2b59033cad12b23c02bba14610495709de5c164682838d811"

  strings:
    $s1  = "function zgQAivyG(NgVSt) {var yYhEjYXy=UHyFIkQUAHWMySfFz[2];for(var yOnIc=0;yOnIc<NgVSt;yOnIc++){MBmgJ+=yYhEjYXy.charAt(Math.flo" ascii
    $s2  = "function zgQAivyG(NgVSt) {var yYhEjYXy=UHyFIkQUAHWMySfFz[2];for(var yOnIc=0;yOnIc<NgVSt;yOnIc++){MBmgJ+=yYhEjYXy.charAt(Math.flo" ascii
    $s3  = "function JAsAZ(laWXfj){return new ActiveXObject(laWXfj);}" fullword ascii
    $s4  = "function eonL(dAkRdm,DuPPRCy){cYRQ = UHyFIkQUAHWMySfFz[11].split(UHyFIkQUAHWMySfFz[12]);DuPPRCy.open(cYRQ[0]+cYRQ[2]+cYRQ[3], dA" ascii
    $s5  = "I<lSdVPm.length;KteiFDMI++) {cWlHmIM+=ElEBm[lSdVPm[KteiFDMI]];}return cWlHmIM.substring(3,cWlHmIM.length);}" fullword ascii
    $s6  = "function stlwrIjvj(JANQdXQMT,LwUMBWO,LFjswIAe){" fullword ascii
    $s7  = "function qmEQt(vGQsZwVr,lSdVPm,NjXwWNvNe){ElEBm=vGQsZwVr.split(NjXwWNvNe);cWlHmIM = UHyFIkQUAHWMySfFz[13];for(KteiFDMI=0;KteiFDM" ascii
    $s8  = "function kItLoL(laWXfj){return laWXfj.ExpandEnvironmentStrings(UHyFIkQUAHWMySfFz[10])}" fullword ascii
    $s9  = "function rypAbxe() {var AzYw=100000;var WhfCEZ = 100;return Math.random()*(AzYw-WhfCEZ)+WhfCEZ;}" fullword ascii
    $s10 = "function qmEQt(vGQsZwVr,lSdVPm,NjXwWNvNe){ElEBm=vGQsZwVr.split(NjXwWNvNe);cWlHmIM = UHyFIkQUAHWMySfFz[13];for(KteiFDMI=0;KteiFDM" ascii
    $s11 = "try{stlwrIjvj(OvxqC[ynUx], rypAbxe() + UHyFIkQUAHWMySfFz[9], 1)}catch(e){}; " fullword ascii
    $s12 = "or(Math.random()*yYhEjYXy.length));}return MBmgJ;}" fullword ascii
    $s13 = "function kxDxl(TDSluMev,RaKBC,UROureUJPA){TDSluMev.open();TDSluMev.type = 1;TDSluMev.write(RaKBC);TDSluMev.position = 0;TDSluMev" ascii
    $s14 = "kRdm, false);DuPPRCy.send();}" fullword ascii
    $s15 = "function eonL(dAkRdm,DuPPRCy){cYRQ = UHyFIkQUAHWMySfFz[11].split(UHyFIkQUAHWMySfFz[12]);DuPPRCy.open(cYRQ[0]+cYRQ[2]+cYRQ[3], dA" ascii
    $s16 = "function kxDxl(TDSluMev,RaKBC,UROureUJPA){TDSluMev.open();TDSluMev.type = 1;TDSluMev.write(RaKBC);TDSluMev.position = 0;TDSluMev" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}