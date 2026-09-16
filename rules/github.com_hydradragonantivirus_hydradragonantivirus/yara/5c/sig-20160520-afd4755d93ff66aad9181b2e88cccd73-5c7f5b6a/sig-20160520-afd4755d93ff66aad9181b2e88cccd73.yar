rule sig_20160520_afd4755d93ff66aad9181b2e88cccd73 {
  meta:
    description = "datamaliciousorder - file 20160520_afd4755d93ff66aad9181b2e88cccd73.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f8442ca05b572b6cca0faf1e955c559d6d9e637aafa18d80df79cef35642ad3"

  strings:
    $s1  = "function UAvWdYqJ(pSvPk) {var WaMSuZAS=saXPfxJORzoYJQcLtUWChBaX[2];for(var XICpS=0;XICpS<pSvPk;XICpS++){VSOOb+=WaMSuZAS.charAt(M" ascii
    $s2  = "function UAvWdYqJ(pSvPk) {var WaMSuZAS=saXPfxJORzoYJQcLtUWChBaX[2];for(var XICpS=0;XICpS<pSvPk;XICpS++){VSOOb+=WaMSuZAS.charAt(M" ascii
    $s3  = "ath.floor(Math.random()*WaMSuZAS.length));}return VSOOb;}" fullword ascii
    $s4  = "function lMkNq(FnzxYNJp,iixfb,wtEVbDXIXF){FnzxYNJp.open();FnzxYNJp.type = 1;FnzxYNJp.write(iixfb);FnzxYNJp.position = 0;FnzxYNJp" ascii
    $s5  = "function wCsjRtj() {var QNUF=100000;var nkKpRF = 100;return Math.random()*(QNUF-nkKpRF)+nkKpRF;}" fullword ascii
    $s6  = "function VGIE(LHfedc,OmiKGFN){Wgpc = saXPfxJORzoYJQcLtUWChBaX[11].split(saXPfxJORzoYJQcLtUWChBaX[12]);OmiKGFN.open(Wgpc[0]+Wgpc[" ascii
    $s7  = "function CLiSuUCMt(xSUWBpidK,EUldYWt,lhFZnqNc){" fullword ascii
    $s8  = "function VGIE(LHfedc,OmiKGFN){Wgpc = saXPfxJORzoYJQcLtUWChBaX[11].split(saXPfxJORzoYJQcLtUWChBaX[12]);OmiKGFN.open(Wgpc[0]+Wgpc[" ascii
    $s9  = "function ymoiya(LMcZcQ){return LMcZcQ.ExpandEnvironmentStrings(saXPfxJORzoYJQcLtUWChBaX[10])}" fullword ascii
    $s10 = "2]+Wgpc[3], LHfedc, false);OmiKGFN.send();}" fullword ascii
    $s11 = "function sNQsU(efYASDYO,PCPPgU,wjDXsarCB){DoGKf=efYASDYO.split(wjDXsarCB);CUCcLvZ = saXPfxJORzoYJQcLtUWChBaX[13];for(ShdvSlpZ=0;" ascii
    $s12 = "function gFFNh(LMcZcQ){return new ActiveXObject(LMcZcQ);}" fullword ascii
    $s13 = "try{CLiSuUCMt(xeqUA[QyCG], wCsjRtj() + saXPfxJORzoYJQcLtUWChBaX[9], 1)}catch(e){}; " fullword ascii
    $s14 = "function lMkNq(FnzxYNJp,iixfb,wtEVbDXIXF){FnzxYNJp.open();FnzxYNJp.type = 1;FnzxYNJp.write(iixfb);FnzxYNJp.position = 0;FnzxYNJp" ascii
    $s15 = "ShdvSlpZ<PCPPgU.length;ShdvSlpZ++) {CUCcLvZ+=DoGKf[PCPPgU[ShdvSlpZ]];}return CUCcLvZ.substring(3,CUCcLvZ.length);}" fullword ascii
    $s16 = "function sNQsU(efYASDYO,PCPPgU,wjDXsarCB){DoGKf=efYASDYO.split(wjDXsarCB);CUCcLvZ = saXPfxJORzoYJQcLtUWChBaX[13];for(ShdvSlpZ=0;" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}