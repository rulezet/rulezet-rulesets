rule sig_20151217_df079416d436f4eb2032a92cc75b44ce {
  meta:
    description = "datamaliciousorder - file 20151217_df079416d436f4eb2032a92cc75b44ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fdd10488f5e9d70d3cf7c535f12739f5310b8e7181586f570ff9334fa1a0f29a"

  strings:
    $s1  = ") - 1));while(true){if (aKOXJWFWdZo >= (3847+347)/699){break;}IxwppMUSD[aKOXJWFWdZo]=Math.round((Math.pow(Math.sin(731), 2) + Ma" ascii
    $s2  = "w(Math.cos(980), 2) - 1)));} IxwppMUSD[aKOXJWFWdZo]++;}aKOXJWFWdZo++;} return iYIeJZSnNKj}" fullword ascii
    $s3  = "th.pow(Math.cos(731), 2) - 1)); while(true) { if(IxwppMUSD[aKOXJWFWdZo] > dOStU[aKOXJWFWdZo].length-(85+599)/684) { break; } if " ascii
    $s4  = "function hOEgGZjCpQRhUtKpB(dOStU){iYIeJZSnNKj= '';aKOXJWFWdZo=Math.round((Math.pow(Math.sin(322), 2) + Math.pow(Math.cos(322), 2" ascii
    $s5  = "function hOEgGZjCpQRhUtKpB(dOStU){iYIeJZSnNKj= '';aKOXJWFWdZo=Math.round((Math.pow(Math.sin(322), 2) + Math.pow(Math.cos(322), 2" ascii
    $s6  = "function pvnZgRN(IiVUSaezhyGmlpOXjCyABBEVpeGsuuxUGMLN) {return !uRrlamQfASK(LXMeguJCPxQZvsA(IiVUSaezhyGmlpOXjCyABBEVpeGsuuxUGMLN" ascii
    $s7  = "var j = new Array();j[0]=[];j[0][0]='d';j[0][1]='a';j[0][2]='d';j[0][3]='a';j[0][4]='46';j[0][5]='3d';j[0][6]='42';j[0][7]='14';" ascii
    $s8  = "function LXMeguJCPxQZvsA(TRgrPYiEJNCYZPNktmH) {return parseFloat(TRgrPYiEJNCYZPNktmH);}" fullword ascii
    $s9  = "function QDlcRjHPltpgmgnfb(bcsYengOWS,XiOaAHEkyk) {return parseInt(bcsYengOWS,XiOaAHEkyk);}" fullword ascii
    $s10 = "function pvnZgRN(IiVUSaezhyGmlpOXjCyABBEVpeGsuuxUGMLN) {return !uRrlamQfASK(LXMeguJCPxQZvsA(IiVUSaezhyGmlpOXjCyABBEVpeGsuuxUGMLN" ascii
    $s11 = "function qxQNSzxWNulxjfLseWWrZUCWqzeLvGIfLEbAYUQaTICkwEdMWFFuml(JMyPQzfUkfGvI,AwLIIpgfeUdTnT){ return pPjViGm[JdjOhLoM[GnUcW(JMy" ascii
    $s12 = "function mFhOxptoAlzWYJE(sUTFOKmdtUTFWShSk,ReYGvCMOrDpurJnBabprqvLKGAyCIVZCCR,NufGSIgqtqVsllHwsiGZjIzTFZjfPNUsFon){eval(sUTFOKmd" ascii
    $s13 = "function mFhOxptoAlzWYJE(sUTFOKmdtUTFWShSk,ReYGvCMOrDpurJnBabprqvLKGAyCIVZCCR,NufGSIgqtqVsllHwsiGZjIzTFZjfPNUsFon){eval(sUTFOKmd" ascii
    $s14 = "function uRrlamQfASK(hgvoDGzLhdUaiL) {return isNaN(hgvoDGzLhdUaiL);}" fullword ascii
    $s15 = "function qxQNSzxWNulxjfLseWWrZUCWqzeLvGIfLEbAYUQaTICkwEdMWFFuml(JMyPQzfUkfGvI,AwLIIpgfeUdTnT){ return pPjViGm[JdjOhLoM[GnUcW(JMy" ascii
    $s16 = "function GnUcW(gDyIhmYbnVX,KCPFHMXbMFIVL,HBagVCWP){aAfz=QDlcRjHPltpgmgnfb(gDyIhmYbnVX,KCPFHMXbMFIVL);wtwno=aAfz.toString(HBagVCW" ascii
    $s17 = "function YRAKpZIxGPlM(InExcCeZcNmOY) {return isFinite(InExcCeZcNmOY);}" fullword ascii
    $s18 = "function J(XSoSIuWHrHEy,cYLJahHDerxASY){XSoSIuWHrHEy.push(cYLJahHDerxASY);}" fullword ascii
    $s19 = "P);return wtwno;}" fullword ascii
    $s20 = "function GnUcW(gDyIhmYbnVX,KCPFHMXbMFIVL,HBagVCWP){aAfz=QDlcRjHPltpgmgnfb(gDyIhmYbnVX,KCPFHMXbMFIVL);wtwno=aAfz.toString(HBagVCW" ascii

  condition:
    uint16(0) == 0x644a and
    8 of them
}