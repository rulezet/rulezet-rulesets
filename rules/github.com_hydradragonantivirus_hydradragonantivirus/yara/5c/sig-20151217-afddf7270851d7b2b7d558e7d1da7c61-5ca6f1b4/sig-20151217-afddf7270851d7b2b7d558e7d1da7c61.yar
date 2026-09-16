rule sig_20151217_afddf7270851d7b2b7d558e7d1da7c61 {
  meta:
    description = "datamaliciousorder - file 20151217_afddf7270851d7b2b7d558e7d1da7c61.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "234f7e12954683987da92304a3159af6ec6b1d6678cf735c540f107cffec8b58"

  strings:
    $s1  = "function bJPNrdFEzEQNKxxmy(Rgxms){vZeBRYDXPMI= '';wDVQmleHsOG=Math.round((Math.pow(Math.sin(131), 2) + Math.pow(Math.cos(131), 2" ascii
    $s2  = ") - 1));while(true){if (wDVQmleHsOG >= (-32+224)/32){break;}DUciqcdyf[wDVQmleHsOG]=Math.round((Math.pow(Math.sin(236), 2) + Math" ascii
    $s3  = "ow(Math.cos(510), 2) - 1)));} DUciqcdyf[wDVQmleHsOG]++;}wDVQmleHsOG++;} return vZeBRYDXPMI}" fullword ascii
    $s4  = ".pow(Math.cos(236), 2) - 1)); while(true) { if(DUciqcdyf[wDVQmleHsOG] > Rgxms[wDVQmleHsOG].length-(-338+714)/376) { break; } if " ascii
    $s5  = "function bJPNrdFEzEQNKxxmy(Rgxms){vZeBRYDXPMI= '';wDVQmleHsOG=Math.round((Math.pow(Math.sin(131), 2) + Math.pow(Math.cos(131), 2" ascii
    $s6  = "function wvUqlBA(iqfHDbUARpGaeOlGdQoAksCPJayGDflcXPJk) {return !kqsSxDRXQYA(fHGLArMOKmkJify(iqfHDbUARpGaeOlGdQoAksCPJayGDflcXPJk" ascii
    $s7  = "var J = new Array();J[0]=[];J[0][0]='d';J[0][1]='a';J[0][2]='d';J[0][3]='a';J[0][4]='46';J[0][5]='3d';J[0][6]='42';J[0][7]='14';" ascii
    $s8  = "function kqsSxDRXQYA(ADWmruvOMccHKq) {return isNaN(ADWmruvOMccHKq);}" fullword ascii
    $s9  = "function TPIEF(GNQGRStweZm,TOIrsVxOefczB,RplmeQdo){PVgN=FGBuRtQFrUkrORmTq(GNQGRStweZm,TOIrsVxOefczB);OqOJe=PVgN.toString(RplmeQd" ascii
    $s10 = "function TPIEF(GNQGRStweZm,TOIrsVxOefczB,RplmeQdo){PVgN=FGBuRtQFrUkrORmTq(GNQGRStweZm,TOIrsVxOefczB);OqOJe=PVgN.toString(RplmeQd" ascii
    $s11 = "function wvUqlBA(iqfHDbUARpGaeOlGdQoAksCPJayGDflcXPJk) {return !kqsSxDRXQYA(fHGLArMOKmkJify(iqfHDbUARpGaeOlGdQoAksCPJayGDflcXPJk" ascii
    $s12 = "function FGBuRtQFrUkrORmTq(KedohZiFhq,KMpEHkXjLq) {return parseInt(KedohZiFhq,KMpEHkXjLq);}" fullword ascii
    $s13 = "function rVYYrlUluFcZ(FqCPjSazTTgib) {return isFinite(FqCPjSazTTgib);}" fullword ascii
    $s14 = "function G(awYdfKQBXNsjBm,nHQVIEPxVVVQj,VkDoAhfvhRl) {awYdfKQBXNsjBm[nHQVIEPxVVVQj]=VkDoAhfvhRl;}" fullword ascii
    $s15 = "function lBWbORLgAlVtSFZ(riKbhnsdhSYAfyKEw,WFUShXNdcfmFKcRXreIMjkvdqHwofcNVDU,hLnhiAUfUwdwjJCbVZBipdAVpAjaOBOTxtU){eval(riKbhnsd" ascii
    $s16 = "function u(AwWRaijEGdoW,ZAWpmbjlfFhnfq){AwWRaijEGdoW.push(ZAWpmbjlfFhnfq);}" fullword ascii
    $s17 = "function yOlhvsePVcMeswxSHiwpAHdZulDPxjWeaHHBfYeoBFheKMGfZSfcYe(YgoGiMQsNovUj,dSilxRFoKDJzQB){ return KWycUEK[WHFEiPVa[TPIEF(Ygo" ascii
    $s18 = "o);return OqOJe;}" fullword ascii
    $s19 = "function yOlhvsePVcMeswxSHiwpAHdZulDPxjWeaHHBfYeoBFheKMGfZSfcYe(YgoGiMQsNovUj,dSilxRFoKDJzQB){ return KWycUEK[WHFEiPVa[TPIEF(Ygo" ascii
    $s20 = "function lBWbORLgAlVtSFZ(riKbhnsdhSYAfyKEw,WFUShXNdcfmFKcRXreIMjkvdqHwofcNVDU,hLnhiAUfUwdwjJCbVZBipdAVpAjaOBOTxtU){eval(riKbhnsd" ascii

  condition:
    uint16(0) == 0x4857 and
    8 of them
}