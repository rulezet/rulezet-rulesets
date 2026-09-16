rule sig_20160520_c706585aa6efb6d62e7a66a03027cf02 {
  meta:
    description = "datamaliciousorder - file 20160520_c706585aa6efb6d62e7a66a03027cf02.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "31e4f31ad9098d9bd6320a2ccc3184ef885bf0be7b79cc8b8c081fae8d08c1b3"

  strings:
    $s1  = "function PLeGHdiW(MFyKv) {var PfjAFHet=qkapTjmMcIPeV[2];for(var BjFTz=0;BjFTz<MFyKv;BjFTz++){qAqZi+=PfjAFHet.charAt(Math.floor(M" ascii
    $s2  = "function PLeGHdiW(MFyKv) {var PfjAFHet=qkapTjmMcIPeV[2];for(var BjFTz=0;BjFTz<MFyKv;BjFTz++){qAqZi+=PfjAFHet.charAt(Math.floor(M" ascii
    $s3  = "ath.random()*PfjAFHet.length));}return qAqZi;}" fullword ascii
    $s4  = "iIPl.length;EPTykItf++) {ofHRxbz+=ZAnnM[fqiIPl[EPTykItf]];}return ofHRxbz.substring(3,ofHRxbz.length);}" fullword ascii
    $s5  = "function DIVp(JRlaRk,EcZsNLF){uXUI = qkapTjmMcIPeV[11].split(qkapTjmMcIPeV[12]);EcZsNLF.open(uXUI[0]+uXUI[2]+uXUI[3], JRlaRk, fa" ascii
    $s6  = "function ExpvzB(lbhCDj){return lbhCDj.ExpandEnvironmentStrings(qkapTjmMcIPeV[10])}" fullword ascii
    $s7  = "function DIVp(JRlaRk,EcZsNLF){uXUI = qkapTjmMcIPeV[11].split(qkapTjmMcIPeV[12]);EcZsNLF.open(uXUI[0]+uXUI[2]+uXUI[3], JRlaRk, fa" ascii
    $s8  = "function gYEPj(vybyUviz,AFbjS,PZbajTZEyb){vybyUviz.open();vybyUviz.type = 1;vybyUviz.write(AFbjS);vybyUviz.position = 0;vybyUviz" ascii
    $s9  = "function uQRWY(lbhCDj){return new ActiveXObject(lbhCDj);}" fullword ascii
    $s10 = "function MXXPbrRoB(dhQzYQbGt,rZhiIpO,IodLKgSL){" fullword ascii
    $s11 = "function wujaI(GGigbqQj,fqiIPl,XUDhsNvIg){ZAnnM=GGigbqQj.split(XUDhsNvIg);ofHRxbz = qkapTjmMcIPeV[13];for(EPTykItf=0;EPTykItf<fq" ascii
    $s12 = "function MwoGvNE() {var NXWj=100000;var LgrDHf = 100;return Math.random()*(NXWj-LgrDHf)+LgrDHf;}" fullword ascii
    $s13 = "function wujaI(GGigbqQj,fqiIPl,XUDhsNvIg){ZAnnM=GGigbqQj.split(XUDhsNvIg);ofHRxbz = qkapTjmMcIPeV[13];for(EPTykItf=0;EPTykItf<fq" ascii
    $s14 = "try{MXXPbrRoB(dNgqN[Xual], MwoGvNE() + qkapTjmMcIPeV[9], 1)}catch(e){}; " fullword ascii
    $s15 = "function gYEPj(vybyUviz,AFbjS,PZbajTZEyb){vybyUviz.open();vybyUviz.type = 1;vybyUviz.write(AFbjS);vybyUviz.position = 0;vybyUviz" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}