rule sig_20160523_568c74bd5505a1a946e6790d7d540b47 {
  meta:
    description = "datamaliciousorder - file 20160523_568c74bd5505a1a946e6790d7d540b47.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e58f993995c599fa0b3dd92d5136c4d0403200de4278ced2e2588cd2f6899f2"

  strings:
    $s1  = "function lbTzPvxK(vypKU) {var nqlotaxl=Ggefx[13];for(var ATHzy=0;ATHzy<vypKU;ATHzy++){EbjpK+=nqlotaxl.charAt(Math.floor(Math.ran" ascii
    $s2  = "function jONkeeLNcM(fQlakRQf,rCijxoqnhXLO) {fQlakRQf.Run(rCijxoqnhXLO, 0x1, 0x0);}" fullword ascii
    $s3  = "function lbTzPvxK(vypKU) {var nqlotaxl=Ggefx[13];for(var ATHzy=0;ATHzy<vypKU;ATHzy++){EbjpK+=nqlotaxl.charAt(Math.floor(Math.ran" ascii
    $s4  = "function FbJi(kNvLAT,LHhrMFZ){VAvI = Ggefx[10].split(Ggefx[11]);LHhrMFZ.open(VAvI[0]+VAvI[2]+VAvI[3], kNvLAT, false);LHhrMFZ.sen" ascii
    $s5  = "function ObkXo(hEJiTsvm,DDhKDO,KMCSHJjlK){wYfTt=hEJiTsvm.split(KMCSHJjlK);sKbKPnd = Ggefx[12];for(eakGWVcw=0;eakGWVcw<DDhKDO.len" ascii
    $s6  = "function ufTxNsyhtH() {return/*pnwSYAwXlvpqvIYxjvdHcPlPuGlgmFmJWlPOamITNtWfsJStpEXHdZXKDgdVpVnmcALmJwDRfnGaaxOqdInMKOyuSKhxObPzw" ascii
    $s7  = "function LYJfaAC() {var UPLq=100000;var amctGk = 100;return TitMDeI()*(UPLq-amctGk)+amctGk;}" fullword ascii
    $s8  = "function vKtCLPpFGuWci() {ufTxNsyhtH().Sleep(2394054-488);}" fullword ascii
    $s9  = "gth;eakGWVcw++) {sKbKPnd+=wYfTt[DDhKDO[eakGWVcw]];}return sKbKPnd.substring(3,sKbKPnd.length);}" fullword ascii
    $s10 = "function FbJi(kNvLAT,LHhrMFZ){VAvI = Ggefx[10].split(Ggefx[11]);LHhrMFZ.open(VAvI[0]+VAvI[2]+VAvI[3], kNvLAT, false);LHhrMFZ.sen" ascii
    $s11 = "function eKiSaDc(meTq,xgiQy) {meTq.write(xgiQy);}" fullword ascii
    $s12 = "function jYBrk(XjQqKW){return new ActiveXObject(XjQqKW);}" fullword ascii
    $s13 = "if(JcyN>mdbrY.length) break;" fullword ascii
    $s14 = "function MGdrTlD(dpYZP) {dpYZP.close();}" fullword ascii
    $s15 = "function IqivZK(XjQqKW){return XjQqKW.ExpandEnvironmentStrings(Ggefx[9])}" fullword ascii
    $s16 = "function ObkXo(hEJiTsvm,DDhKDO,KMCSHJjlK){wYfTt=hEJiTsvm.split(KMCSHJjlK);sKbKPnd = Ggefx[12];for(eakGWVcw=0;eakGWVcw<DDhKDO.len" ascii
    $s17 = "dom()*nqlotaxl.length));}return EbjpK;}" fullword ascii
    $s18 = "function TitMDeI(){return Math.random();}" fullword ascii
    $s19 = "function GUGI(IhfbuU) {IhfbuU.open();}" fullword ascii
    $s20 = "function BWrUJZljy(xkyQWX) {var MwJOiaWThU=[];xkyQWX.position=MwJOiaWThU.length*(2364650-399);}" fullword ascii

  condition:
    uint16(0) == 0x1d27 and
    8 of them
}