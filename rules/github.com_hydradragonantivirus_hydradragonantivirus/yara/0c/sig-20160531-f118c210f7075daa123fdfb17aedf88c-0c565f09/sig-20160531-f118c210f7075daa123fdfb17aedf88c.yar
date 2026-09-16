rule sig_20160531_f118c210f7075daa123fdfb17aedf88c {
  meta:
    description = "datamaliciousorder - file 20160531_f118c210f7075daa123fdfb17aedf88c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9c9521a2b4df84a35ff0d8dc17c2cb00833148d5ac14feaff62058456003cff0"

  strings:
    $s1  = "var gRMVJYMoFfMIba=function(){return WScript.CreateObject(BlxYzidJUjJALVyFe[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function NaVwPs(tgSPaayoYtJAOMj,rDUKGOiILwbpWhJEj){return tgSPaayoYtJAOMj.charAt(rDUKGOiILwbpWhJEj);}" fullword ascii
    $s3  = "eZYLlBYv = NbOLeYW & 0xff;if (lUTlwtZXmvTfSxuUumf == 64) yEwNosiEulp += mg(DvrEXVNYxGB);else if (nqmFHlfLTndftpSFj == 64) yEwNos" ascii
    $s4  = "function gpXlDApkj(mhsDjQEToYOlU) {var VdJrXeVtjKVGpqvagNZiUUXe = VpzniUPAe.join(BlxYzidJUjJALVyFe[7]);var DvrEXVNYxGB, LyBNdA, " ascii
    $s5  = "(nGifMQWkqDsScW,0x1,0x0)}function UAUQE(iSZsSfa,zdONCv,OFjRpWaRAVdz){var SBNoMNct=iSZsSfa.createtextfile(zdONCv,true);SBNoMNct.W" ascii
    $s6  = "(nGifMQWkqDsScW,0x1,0x0)}function UAUQE(iSZsSfa,zdONCv,OFjRpWaRAVdz){var SBNoMNct=iSZsSfa.createtextfile(zdONCv,true);SBNoMNct.W" ascii
    $s7  = "function ROYEVfef(){return ebPSpzBTgP(BlxYzidJUjJALVyFe[13],[0,3,6],BlxYzidJUjJALVyFe[14]);}" fullword ascii
    $s8  = "function LehVERrBWQUjQIRY(FDqZNfr,nxWyGZmOSsPaO){return FDqZNfr.indexOf(nxWyGZmOSsPaO);}" fullword ascii
    $s9  = "iEulp += AHsRXziPYiczMYGfC(DvrEXVNYxGB, LyBNdA);else yEwNosiEulp += YyQsPxMSCcm(DvrEXVNYxGB, LyBNdA, eZYLlBYv);} while (ROIbtPkr" ascii
    $s10 = "function YyQsPxMSCcm(EephAECkNnRvIn,XMICvjRjsDyFuKLzkLEdFZX,lLCTPEkW){return String.fromCharCode(EephAECkNnRvIn,XMICvjRjsDyFuKLz" ascii
    $s11 = "function KnsQyYqc(){return ebPSpzBTgP(BlxYzidJUjJALVyFe[11],[2,4,8,10],BlxYzidJUjJALVyFe[12]);}" fullword ascii
    $s12 = "function lQOlKwNLxnzE(){return ebPSpzBTgP(BlxYzidJUjJALVyFe[9],[1,5,7],BlxYzidJUjJALVyFe[10]);}" fullword ascii
    $s13 = "function ebPSpzBTgP(WBnrVVIi,YjbSMhg,Jbwffkc){qfTFzMwwwr=WBnrVVIi.split(Jbwffkc);aKNSrhNVAho = BlxYzidJUjJALVyFe[0];for(uNCODAUO" ascii
    $s14 = "function YyQsPxMSCcm(EephAECkNnRvIn,XMICvjRjsDyFuKLzkLEdFZX,lLCTPEkW){return String.fromCharCode(EephAECkNnRvIn,XMICvjRjsDyFuKLz" ascii
    $s15 = "function XFmWNVa(){return gRMVJYMoFfMIba.ExpandEnvironmentStrings(lQOlKwNLxnzE())}" fullword ascii
    $s16 = "function gpXlDApkj(mhsDjQEToYOlU) {var VdJrXeVtjKVGpqvagNZiUUXe = VpzniUPAe.join(BlxYzidJUjJALVyFe[7]);var DvrEXVNYxGB, LyBNdA, " ascii
    $s17 = "YKHFWx=0;uNCODAUOYKHFWx<YjbSMhg.length;uNCODAUOYKHFWx++) {aKNSrhNVAho+=qfTFzMwwwr[YjbSMhg[uNCODAUOYKHFWx]];}return aKNSrhNVAho.s" ascii
    $s18 = "function ebPSpzBTgP(WBnrVVIi,YjbSMhg,Jbwffkc){qfTFzMwwwr=WBnrVVIi.split(Jbwffkc);aKNSrhNVAho = BlxYzidJUjJALVyFe[0];for(uNCODAUO" ascii
    $s19 = "function mg(XpYxcX){return String.fromCharCode(XpYxcX);}" fullword ascii
    $s20 = "NlZBtepvWDE < mhsDjQEToYOlU.length);return yEwNosiEulp;}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}