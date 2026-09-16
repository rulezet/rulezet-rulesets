rule sig_20160520_329f70dc58a55d376c390e0c3e8ab183 {
  meta:
    description = "datamaliciousorder - file 20160520_329f70dc58a55d376c390e0c3e8ab183.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "53a82f86289b9de1a5f8ad3f2aab70b71cd5343e60ab6f2a98f433b51be60446"

  strings:
    $s1  = "function NZCtOVam(AodbI) {var ulQwgxlE=NBIILeWDSPzRkQtdMxcu[2];for(var Rjppr=0;Rjppr<AodbI;Rjppr++){wJqYH+=ulQwgxlE.charAt(Math." ascii
    $s2  = "function NZCtOVam(AodbI) {var ulQwgxlE=NBIILeWDSPzRkQtdMxcu[2];for(var Rjppr=0;Rjppr<AodbI;Rjppr++){wJqYH+=ulQwgxlE.charAt(Math." ascii
    $s3  = "function xAvmG(BVoOjbtC,kfZaPY,gNJZkUeal){adVfE=BVoOjbtC.split(gNJZkUeal);LrCByxo = NBIILeWDSPzRkQtdMxcu[13];for(ZLsIiQTx=0;ZLsI" ascii
    $s4  = "if (kucGYwG==0) break;" fullword ascii
    $s5  = "function rMqb(OiGOXv,RgdrVFS){prsB = NBIILeWDSPzRkQtdMxcu[11].split(NBIILeWDSPzRkQtdMxcu[12]);RgdrVFS.open(prsB[0]+prsB[2]+prsB[" ascii
    $s6  = "function wpgMT(AlhAGxYc,bnpMC,HLpBcrWQxM){AlhAGxYc.open();AlhAGxYc.type = 1;AlhAGxYc.write(bnpMC);AlhAGxYc.position = 0;AlhAGxYc" ascii
    $s7  = "floor(Math.random()*ulQwgxlE.length));}return wJqYH;}" fullword ascii
    $s8  = "function DQpTK(hidFRt){return new ActiveXObject(hidFRt);}" fullword ascii
    $s9  = "function rMqb(OiGOXv,RgdrVFS){prsB = NBIILeWDSPzRkQtdMxcu[11].split(NBIILeWDSPzRkQtdMxcu[12]);RgdrVFS.open(prsB[0]+prsB[2]+prsB[" ascii
    $s10 = "function wpgMT(AlhAGxYc,bnpMC,HLpBcrWQxM){AlhAGxYc.open();AlhAGxYc.type = 1;AlhAGxYc.write(bnpMC);AlhAGxYc.position = 0;AlhAGxYc" ascii
    $s11 = "function eSIqtD(hidFRt){return hidFRt.ExpandEnvironmentStrings(NBIILeWDSPzRkQtdMxcu[10])}" fullword ascii
    $s12 = "try{kucGYwG=iFEsXQLov(MbZNo[eIYA], uOkhFkS() + NBIILeWDSPzRkQtdMxcu[9], 1)}catch(e){}; " fullword ascii
    $s13 = "iQTx<kfZaPY.length;ZLsIiQTx++) {LrCByxo+=adVfE[kfZaPY[ZLsIiQTx]];}return LrCByxo.substring(3,LrCByxo.length);}" fullword ascii
    $s14 = "function uOkhFkS() {var OOwD=100000;var iykINQ = 100;return Math.random()*(OOwD-iykINQ)+iykINQ;}" fullword ascii
    $s15 = "function xAvmG(BVoOjbtC,kfZaPY,gNJZkUeal){adVfE=BVoOjbtC.split(gNJZkUeal);LrCByxo = NBIILeWDSPzRkQtdMxcu[13];for(ZLsIiQTx=0;ZLsI" ascii
    $s16 = "3], OiGOXv, false);RgdrVFS.send();}" fullword ascii
    $s17 = "function iFEsXQLov(kSjykcyEn,pIvwQFV,rqFDcaDs){" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}