rule sig_20160523_044343fd39282f035f2550c8298ccbae {
  meta:
    description = "datamaliciousorder - file 20160523_044343fd39282f035f2550c8298ccbae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d1f020639434e7c51970bd0f2721d155d508794aa18facc655b086669dec9772"

  strings:
    $s1  = "function BtnwDbPgMu(FQeHtVFP,yMzjWHGPUagj) {FQeHtVFP.Run(yMzjWHGPUagj, 0x1, 0x0);}" fullword ascii
    $s2  = "function WlmXLIZp(KvspH) {var QOCGMhLf=yVctJc[13];for(var RTaOK=0;RTaOK<KvspH;RTaOK++){CIZgz+=QOCGMhLf.charAt(Math.floor(Math.ra" ascii
    $s3  = "function WlmXLIZp(KvspH) {var QOCGMhLf=yVctJc[13];for(var RTaOK=0;RTaOK<KvspH;RTaOK++){CIZgz+=QOCGMhLf.charAt(Math.floor(Math.ra" ascii
    $s4  = "function bZKjrgyFju() {return/*ukSbIJezdCtcbdvxrBiRSWqHAlnDbqEprUnjnzntDxXQPFcAceuqZnpdCaPRouCtbnPHTjQeNPHagauBRBNmxOqwBDbQThCBh" ascii
    $s5  = "function untaEQBVvOjMi() {bZKjrgyFju().Sleep(2287292-698);}" fullword ascii
    $s6  = "function lzui(fPNuLo) {fPNuLo.open();}" fullword ascii
    $s7  = "function Kuxqy(ELOlzT){return new ActiveXObject(ELOlzT);}" fullword ascii
    $s8  = "function bBZah(jdhtgDwM,hFzrOP,xxSgzveIX){uvAwK=jdhtgDwM.split(xxSgzveIX);XQJvEpQ = yVctJc[12];for(fPvWHLXk=0;fPvWHLXk<hFzrOP.le" ascii
    $s9  = "ngth;fPvWHLXk++) {XQJvEpQ+=uvAwK[hFzrOP[fPvWHLXk]];}return XQJvEpQ.substring(3,XQJvEpQ.length);}" fullword ascii
    $s10 = "function qxjKAnh(DbSU,eEswc) {DbSU.write(eEswc);}" fullword ascii
    $s11 = "function bBZah(jdhtgDwM,hFzrOP,xxSgzveIX){uvAwK=jdhtgDwM.split(xxSgzveIX);XQJvEpQ = yVctJc[12];for(fPvWHLXk=0;fPvWHLXk<hFzrOP.le" ascii
    $s12 = "function fBPK(zlHhJM,bQMNRzv){GMBb = yVctJc[10].split(yVctJc[11]);bQMNRzv.open(GMBb[0]+GMBb[2]+GMBb[3], zlHhJM, false);bQMNRzv.s" ascii
    $s13 = "function fOnHGfs(){return Math.random();}" fullword ascii
    $s14 = "function FPVvhri() {var nZqP=100000;var uRhRcv = 100;return fOnHGfs()*(nZqP-uRhRcv)+uRhRcv;}" fullword ascii
    $s15 = "if(hnkg>HbvKN.length) break;" fullword ascii
    $s16 = "function fBPK(zlHhJM,bQMNRzv){GMBb = yVctJc[10].split(yVctJc[11]);bQMNRzv.open(GMBb[0]+GMBb[2]+GMBb[3], zlHhJM, false);bQMNRzv.s" ascii
    $s17 = "function yKbGZvS(PGuYk) {PGuYk.close();}" fullword ascii
    $s18 = "function Mkav(NhamZUe,ohsIzlI) {NhamZUe.saveToFile(ohsIzlI, 2);}" fullword ascii
    $s19 = "function dRwYDoTWt(axZyZm) {var JvJaOaEKDP=[];axZyZm.position=JvJaOaEKDP.length*(3384822-542);}" fullword ascii
    $s20 = "function OOiBwF(ELOlzT){return ELOlzT.ExpandEnvironmentStrings(yVctJc[9])}" fullword ascii

  condition:
    uint16(0) == 0x1927 and
    8 of them
}