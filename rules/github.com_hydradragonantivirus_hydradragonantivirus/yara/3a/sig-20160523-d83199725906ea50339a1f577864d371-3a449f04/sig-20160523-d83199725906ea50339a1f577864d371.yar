rule sig_20160523_d83199725906ea50339a1f577864d371 {
  meta:
    description = "datamaliciousorder - file 20160523_d83199725906ea50339a1f577864d371.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "74792936fbfb8547aef55aa50c32bbe060b4d127164ec1e48355982e9c2e1969"

  strings:
    $s1  = "function EvpjTplhXb(ZWecqWKs,RQVclamyqKDp) {ZWecqWKs.Run(RQVclamyqKDp, 0x1, 0x0);}" fullword ascii
    $s2  = "function ZJaYrMRJ(eoeur) {var jtcqQDBF=WknDsgQDd[13];for(var shbZE=0;shbZE<eoeur;shbZE++){JuSBo+=jtcqQDBF.charAt(Math.floor(Math" ascii
    $s3  = "function ZJaYrMRJ(eoeur) {var jtcqQDBF=WknDsgQDd[13];for(var shbZE=0;shbZE<eoeur;shbZE++){JuSBo+=jtcqQDBF.charAt(Math.floor(Math" ascii
    $s4  = "function KktaHdubnU() {return/*zsFfawvXyntJQPJddnFKvDbUczuwvKlDZzNYbaBnzgNTkHkPmNpVySBAErxTmFCiMPyJWFsWJDwqFobKCaAllTlmPnQFGNqKW" ascii
    $s5  = ".random()*jtcqQDBF.length));}return JuSBo;}" fullword ascii
    $s6  = "if(OsSK>asbWJ.length) break;" fullword ascii
    $s7  = "function MJsZu(PFtuWhPu,UTYCii,svoURbabz){EuFMG=PFtuWhPu.split(svoURbabz);NRksizi = WknDsgQDd[12];for(NEjUxBbQ=0;NEjUxBbQ<UTYCii" ascii
    $s8  = "function SQUYG(upelNBZX,ycywl,IVBDAYKPGy){itcE(upelNBZX);XYqbbmSM(upelNBZX);hdKlVfZ(upelNBZX,ycywl);CZKusFtYw(upelNBZX);HGWZ(upe" ascii
    $s9  = "function tAmiXGy(APeht) {APeht.close();}" fullword ascii
    $s10 = "function SQUYG(upelNBZX,ycywl,IVBDAYKPGy){itcE(upelNBZX);XYqbbmSM(upelNBZX);hdKlVfZ(upelNBZX,ycywl);CZKusFtYw(upelNBZX);HGWZ(upe" ascii
    $s11 = "function imwrvI(gGOnOw){return gGOnOw.ExpandEnvironmentStrings(WknDsgQDd[9])}" fullword ascii
    $s12 = "function hdKlVfZ(FxiR,cwDIk) {FxiR.write(cwDIk);}" fullword ascii
    $s13 = ".length;NEjUxBbQ++) {NRksizi+=EuFMG[UTYCii[NEjUxBbQ]];}return NRksizi.substring(3,NRksizi.length);}" fullword ascii
    $s14 = "function XYqbbmSM(NFdhUxFqm) {NFdhUxFqm.type=1;}" fullword ascii
    $s15 = "function MJsZu(PFtuWhPu,UTYCii,svoURbabz){EuFMG=PFtuWhPu.split(svoURbabz);NRksizi = WknDsgQDd[12];for(NEjUxBbQ=0;NEjUxBbQ<UTYCii" ascii
    $s16 = "function EOSuQ(gGOnOw){return new ActiveXObject(gGOnOw);}" fullword ascii
    $s17 = "function itcE(vNgIuf) {vNgIuf.open();}" fullword ascii
    $s18 = "function dVXd(Rzinmb,sgATQAx){kXaF = WknDsgQDd[10].split(WknDsgQDd[11]);sgATQAx.open(kXaF[0]+kXaF[2]+kXaF[3], Rzinmb, false);sgA" ascii
    $s19 = "function BJsuYmW(){return Math.random();}" fullword ascii
    $s20 = "function UeVanEZ() {var kWgy=100000;var BgIGyT = 100;return BJsuYmW()*(kWgy-BgIGyT)+BgIGyT;}" fullword ascii

  condition:
    uint16(0) == 0x0527 and
    8 of them
}