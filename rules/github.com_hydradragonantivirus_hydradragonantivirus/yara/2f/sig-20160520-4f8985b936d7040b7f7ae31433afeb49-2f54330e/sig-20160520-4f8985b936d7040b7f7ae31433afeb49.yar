rule sig_20160520_4f8985b936d7040b7f7ae31433afeb49 {
  meta:
    description = "datamaliciousorder - file 20160520_4f8985b936d7040b7f7ae31433afeb49.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1228060d5a7b59532fc2913735ac0da1dad666a1427b51c67c3bf201e067002a"

  strings:
    $s1  = "function VumGLAMP(DQpnv) {var VHtLTbZx=mabctsyN[2];for(var rgvfr=0;rgvfr<DQpnv;rgvfr++){jBGBV+=VHtLTbZx.charAt(Math.floor(Math.r" ascii
    $s2  = "function VumGLAMP(DQpnv) {var VHtLTbZx=mabctsyN[2];for(var rgvfr=0;rgvfr<DQpnv;rgvfr++){jBGBV+=VHtLTbZx.charAt(Math.floor(Math.r" ascii
    $s3  = "function svCIhe(Hodras){return Hodras.ExpandEnvironmentStrings(mabctsyN[10])}" fullword ascii
    $s4  = "function Nldd(ojESFz,kslniud){cirH = mabctsyN[11].split(mabctsyN[12]);kslniud.open(cirH[0]+cirH[2]+cirH[3], ojESFz, false);kslni" ascii
    $s5  = "if (qmuQlGM==0) break;" fullword ascii
    $s6  = "try{qmuQlGM=JImMUFyPi(IMuXP[GgVC], qeAjGyO() + mabctsyN[9], 1)}catch(e){}; " fullword ascii
    $s7  = "function xtcCw(AXZWsvmV,yjHUY,xbOxYNeaWH){AXZWsvmV.open();AXZWsvmV.type = 1;AXZWsvmV.write(yjHUY);AXZWsvmV.position = 0;AXZWsvmV" ascii
    $s8  = "function bAQCy(Hodras){return new ActiveXObject(Hodras);}" fullword ascii
    $s9  = "function Nldd(ojESFz,kslniud){cirH = mabctsyN[11].split(mabctsyN[12]);kslniud.open(cirH[0]+cirH[2]+cirH[3], ojESFz, false);kslni" ascii
    $s10 = "function dtBOV(eZbuornt,UimkvC,jJPfOkCVn){PZqNR=eZbuornt.split(jJPfOkCVn);OeZgNeK = mabctsyN[13];for(EEEsivjo=0;EEEsivjo<UimkvC." ascii
    $s11 = "function xtcCw(AXZWsvmV,yjHUY,xbOxYNeaWH){AXZWsvmV.open();AXZWsvmV.type = 1;AXZWsvmV.write(yjHUY);AXZWsvmV.position = 0;AXZWsvmV" ascii
    $s12 = "length;EEEsivjo++) {OeZgNeK+=PZqNR[UimkvC[EEEsivjo]];}return OeZgNeK.substring(3,OeZgNeK.length);}" fullword ascii
    $s13 = "function JImMUFyPi(LrmEkejgg,xbePWUJ,fyrHsBzi){" fullword ascii
    $s14 = "andom()*VHtLTbZx.length));}return jBGBV;}" fullword ascii
    $s15 = "function dtBOV(eZbuornt,UimkvC,jJPfOkCVn){PZqNR=eZbuornt.split(jJPfOkCVn);OeZgNeK = mabctsyN[13];for(EEEsivjo=0;EEEsivjo<UimkvC." ascii
    $s16 = "function qeAjGyO() {var CaaT=100000;var grIuFV = 100;return Math.random()*(CaaT-grIuFV)+grIuFV;}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}