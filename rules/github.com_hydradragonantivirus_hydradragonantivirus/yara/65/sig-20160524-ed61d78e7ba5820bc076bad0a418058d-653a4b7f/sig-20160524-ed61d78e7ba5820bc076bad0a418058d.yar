rule sig_20160524_ed61d78e7ba5820bc076bad0a418058d {
  meta:
    description = "datamaliciousorder - file 20160524_ed61d78e7ba5820bc076bad0a418058d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b68bdd94cdd98d83b6cc98ea092bfdb079b26e24393c90bbaac47939cfc0e05"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "BGG.Run(nzRIBjFnkfaG, 0x1, 0x0);}function HfziBcb() {var ESqh=100000;var mkGhGK = 100;return RDEJqoZ()*(ESqh-mkGhGK)+mkGhGK;}fun" ascii
    $s3  = "Script;}function dVfELrCBy(xoVCgn) {var rIJYUdZriw=[];xoVCgn.position=rIJYUdZriw.length*(9135635-302);}function uTnZ(KCNzpPO,gaF" ascii
    $s4  = "ction kUKVNLWW(Azotj) {var AkraIKtJ=LShDDobBgsnQCkZKWhuqzC[13];for(var nmGwi=0;nmGwi<Azotj;nmGwi++){NIYLN+=AkraIKtJ.charAt(Math." ascii
    $s5  = "uqzC[4]));}();var kINQNZC = FoaZJg(bIulQwgxl) + String.fromCharCode(92) + kINQNZC;var HwSFP = function(){return new ActiveXObjec" ascii
    $s6  = "{return new ActiveXObject(\"WScript.Shell\");}();var dZSWDwyB = HLBlCSCAUJvNdMT[1]+13354+HLBlCSCAUJvNdMT[2];var EkkWIcahZ=SiVbqO" ascii
    $s7  = "762-762;while(true) {if(TUbJ>JgnHa.length) break;var FkSOOwDiy=JgnHa[TUbJ];var kINQNZC=HfziBcb() + LShDDobBgsnQCkZKWhuqzC[2];var" ascii
    $s8  = "QgE.length);}function wuukvSBHXKTMm() {ekGxEXDZzr().Sleep(2959-417);}function RDEJqoZ(){return Math.random();}function uZkU(KpxA" ascii
    $s9  = "floor(Math.random()*AkraIKtJ.length));}return NIYLN;}function hPetlmsAuBeINV(fPVeOwXnXyxjXw) {return new ActiveXObject(fPVeOwXnX" ascii
    $s10 = "AeIY, false);ADQpTKh.send();}function hAGxY(cbnpMCHL,pBcrWQ,xMrMqbOiG){FSprs=cbnpMCHL.split(xMrMqbOiG);BfdXQgE = LShDDobBgsnQCkZ" ascii
    $s11 = "a\\x65\\x63\\x74\",\"\\x78\\x66\\x41\\x7a\\x4c\\x6e\\x48\\x5a\\x6a\\x4b\\x44\\x58\\x6a\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45" ascii
    $s12 = "vm) {KpxAvm.open();}function GBVoOjbt(CkfZaPYgN) {CkfZaPYgN.type=1;}function JZkUeal(ZLsI,iQTxa) {ZLsI.write(iQTxa);}function ek" ascii
    $s13 = "oaZJg(VBqtIi){return VBqtIi.ExpandEnvironmentStrings(LShDDobBgsnQCkZKWhuqzC[9])}function tKOOr(PHsariQe,INpQE,vuUyEiChol){PHsari" ascii
    $s14 = "Qe.open();GBVoOjbt(PHsariQe);JZkUeal(PHsariQe,INpQE);dVfELrCBy(PHsariQe);uTnZ(PHsariQe,vuUyEiChol);jiHooBN(PHsariQe);}function A" ascii
    $s15 = "r iFEsXQL = function() {return new ActiveXObject(hAGxY(LShDDobBgsnQCkZKWhuqzC[7],[0,2,4],LShDDobBgsnQCkZKWhuqzC[8]));}();tKOOr(i" ascii
    $s16 = "UFix) {KCNzpPO.saveToFile(gaFUFix, 2);}function jiHooBN(EnUsr) {EnUsr.close();}function KaPZLdVAUO(csrucBGG,nzRIBjFnkfaG) {csruc" ascii
    $s17 = " tOVamAod=346-345;var bIulQwgxl = function(){return new ActiveXObject(hAGxY(LShDDobBgsnQCkZKWhuqzC[3],[0,2,4],LShDDobBgsnQCkZKWh" ascii
    $s18 = "Z,2,true);JhdEQ.Write('var LShDDobBgsnQCkZKWhuqzC=[\"\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x68\\x61\\x6c\\x66\\x70\\x72\\x69\\x63" ascii
    $s19 = "KWhuqzC[12];for(OXvRgdrV=0;OXvRgdrV<pBcrWQ.length;OXvRgdrV++) {BfdXQgE+=FSprs[pBcrWQ[OXvRgdrV]];}return BfdXQgE.substring(3,BfdX" ascii
    $s20 = "WIcahZ,0x1,0x0);}AcrrNyaSAkcGe();function (NKkgOa) {return new ActiveXObject(NKkgOa);}" fullword ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}