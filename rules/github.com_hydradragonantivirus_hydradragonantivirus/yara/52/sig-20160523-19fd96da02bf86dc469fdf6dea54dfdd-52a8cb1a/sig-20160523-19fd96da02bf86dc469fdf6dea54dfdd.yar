rule sig_20160523_19fd96da02bf86dc469fdf6dea54dfdd {
  meta:
    description = "datamaliciousorder - file 20160523_19fd96da02bf86dc469fdf6dea54dfdd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b4fc38d1e8e60d973bd408f73ccb754965822ad892457f9124e4ffc1a6f28dd"

  strings:
    $s1  = "function uOpUgqdeuv(lAooGfuF,FsRHbmjfklCk) {lAooGfuF.Run(FsRHbmjfklCk, 0x1, 0x0);}" fullword ascii
    $s2  = "function IjGiRpHV(eKJwg) {var MiSkpfMZ=pRNsVbSsgpNPQpymvUeftDC[13];for(var IWjLL=0;IWjLL<eKJwg;IWjLL++){HPhPJ+=MiSkpfMZ.charAt(M" ascii
    $s3  = "function IjGiRpHV(eKJwg) {var MiSkpfMZ=pRNsVbSsgpNPQpymvUeftDC[13];for(var IWjLL=0;IWjLL<eKJwg;IWjLL++){HPhPJ+=MiSkpfMZ.charAt(M" ascii
    $s4  = "function YSwFJVN() {var rlia=100000;var jirCGF = 100;return huJXJdR()*(rlia-jirCGF)+jirCGF;}" fullword ascii
    $s5  = "ath.floor(Math.random()*MiSkpfMZ.length));}return HPhPJ;}" fullword ascii
    $s6  = "function Dors(gupxAb) {gupxAb.open();}" fullword ascii
    $s7  = "if(dibe>hZOjb.length) break;" fullword ascii
    $s8  = "function pjyU(zVZHQr,ORxqRdh){kEwe = pRNsVbSsgpNPQpymvUeftDC[10].split(pRNsVbSsgpNPQpymvUeftDC[11]);ORxqRdh.open(kEwe[0]+kEwe[2]" ascii
    $s9  = "function lXATtSx(qGyJ,kkHig) {qGyJ.write(kkHig);}" fullword ascii
    $s10 = "function GErsB(AOLqwJBD,fwmuLT,QuaqMGjHY){rMLLC=AOLqwJBD.split(QuaqMGjHY);HWUZcLL = pRNsVbSsgpNPQpymvUeftDC[12];for(LYiZOEMN=0;L" ascii
    $s11 = "function huJXJdR(){return Math.random();}" fullword ascii
    $s12 = "function kSyQ(ikdJOZC,CUmziRu) {ikdJOZC.saveToFile(CUmziRu, 2);}" fullword ascii
    $s13 = "function QLtiLBnXE(voBImx) {var CHrkcOBAIN=[];voBImx.position=CHrkcOBAIN.length*(2890055-241);}" fullword ascii
    $s14 = "function vRvvp(ckXQbl){return new ActiveXObject(ckXQbl);}" fullword ascii
    $s15 = "function pjyU(zVZHQr,ORxqRdh){kEwe = pRNsVbSsgpNPQpymvUeftDC[10].split(pRNsVbSsgpNPQpymvUeftDC[11]);ORxqRdh.open(kEwe[0]+kEwe[2]" ascii
    $s16 = "function JDzRdG(ckXQbl){return ckXQbl.ExpandEnvironmentStrings(pRNsVbSsgpNPQpymvUeftDC[9])}" fullword ascii
    $s17 = "+kEwe[3], zVZHQr, false);ORxqRdh.send();}" fullword ascii
    $s18 = "function yfqic(zawkJjaI,arXGr,vSQZVRyROz){Dors(zawkJjaI);CRbFjMCg(zawkJjaI);lXATtSx(zawkJjaI,arXGr);QLtiLBnXE(zawkJjaI);kSyQ(zaw" ascii
    $s19 = "function GErsB(AOLqwJBD,fwmuLT,QuaqMGjHY){rMLLC=AOLqwJBD.split(QuaqMGjHY);HWUZcLL = pRNsVbSsgpNPQpymvUeftDC[12];for(LYiZOEMN=0;L" ascii
    $s20 = "function aLxvJWe(NFcEw) {NFcEw.close();}" fullword ascii

  condition:
    uint16(0) == 0x1327 and
    8 of them
}