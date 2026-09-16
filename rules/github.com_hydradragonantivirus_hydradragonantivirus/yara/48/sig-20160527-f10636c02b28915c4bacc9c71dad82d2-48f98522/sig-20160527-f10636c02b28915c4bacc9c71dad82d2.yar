rule sig_20160527_f10636c02b28915c4bacc9c71dad82d2 {
  meta:
    description = "datamaliciousorder - file 20160527_f10636c02b28915c4bacc9c71dad82d2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8659dc1033100f649b998078f4d328164f0870c2fee31a65139cf5671f551f67"

  strings:
    $s1  = "function acWFLZ() {return WScript;}function tcIxKWS(){return ymTvnDHfW.ExpandEnvironmentStrings(UsmJHSc())}" fullword ascii
    $s2  = "function xYKcSRHhajBLXOwzWfEMothl(IIcrVFhJeLgLFn,kYbYYl){return IIcrVFhJeLgLFn.charAt(kYbYYl);}" fullword ascii
    $s3  = "MhIAPvFmJbM.length);return ImGZmLtKJV;}" fullword ascii
    $s4  = "ing.fromCharCode(92)+KLVNhMAdjPixeGdgWTWm[4],true);" fullword ascii
    $s5  = "var ymTvnDHfW=function(){return acWFLZ().CreateObject(KLVNhMAdjPixeGdgWTWm[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s6  = "var Cqzcd = beJnePczYKpTI.createtextfile(ymTvnDHfW.ExpandEnvironmentStrings(KLVNhMAdjPixeGdgWTWm[2]+KLVNhMAdjPixeGdgWTWm[3])+Str" ascii
    $s7  = "function woibAPOLkq(KDMhIAPvFmJbM) {var zIWPKFPUTbRtPXPnrxHt = xfhrFUTaQWXHNolayLbHKa.join(KLVNhMAdjPixeGdgWTWm[6]);var MAMqWDJK" ascii
    $s8  = "function XHdaKVbbLVYqjcgTsteP(SzJcxYvaIRM,zIdugBnwmYQEtzjPGko){return String.fromCharCode(SzJcxYvaIRM,zIdugBnwmYQEtzjPGko);}" fullword ascii
    $s9  = "function Lpymuew(PksEUGXHcmAN,xbpLKnlFXbNuSF) {var NFLVIgbPhA=[KLVNhMAdjPixeGdgWTWm[15]];PksEUGXHcmAN[NFLVIgbPhA[0]](xbpLKnlFXbN" ascii
    $s10 = "4];for(LEltgFOOB=0;LEltgFOOB<GtyYNtHlbpaxN.length;LEltgFOOB++) {WhVVBfuLrQoh+=dlSMhAVOt[GtyYNtHlbpaxN[LEltgFOOB]];}return WhVVBf" ascii
    $s11 = "function UsmJHSc(){return AKHIhAKuwKp(KLVNhMAdjPixeGdgWTWm[8],[1,5,7],KLVNhMAdjPixeGdgWTWm[9]);}" fullword ascii
    $s12 = "function PsSHwZ(){return AKHIhAKuwKp(KLVNhMAdjPixeGdgWTWm[10],[2,4,8,10],KLVNhMAdjPixeGdgWTWm[11]);}" fullword ascii
    $s13 = "V += fI(MAMqWDJKEIFigOjS);else if (ikFHlqGbtqTMhhKVeIy == 64) ImGZmLtKJV += XHdaKVbbLVYqjcgTsteP(MAMqWDJKEIFigOjS, CWuZhrVdx);el" ascii
    $s14 = "function AKHIhAKuwKp(RGnQg,GtyYNtHlbpaxN,wOLFkkzAkCWt){dlSMhAVOt=RGnQg.split(wOLFkkzAkCWt);WhVVBfuLrQoh = KLVNhMAdjPixeGdgWTWm[1" ascii
    $s15 = "function UkPFcsok(){return AKHIhAKuwKp(KLVNhMAdjPixeGdgWTWm[12],[0,3,6],KLVNhMAdjPixeGdgWTWm[13]);}" fullword ascii
    $s16 = "se ImGZmLtKJV += xWfmpMBJefCkhVxcGaPsIanh(MAMqWDJKEIFigOjS, CWuZhrVdx, GvqKgMQDPndwEOXXLxnRKNb);} while (nZImEgxjWPRvLXFHTm < KD" ascii
    $s17 = "function CsbDOuquzmtmf(ffKzhx,KtdOrsYRcKtpMKjrP){return ffKzhx.indexOf(KtdOrsYRcKtpMKjrP);}" fullword ascii
    $s18 = "function woibAPOLkq(KDMhIAPvFmJbM) {var zIWPKFPUTbRtPXPnrxHt = xfhrFUTaQWXHNolayLbHKa.join(KLVNhMAdjPixeGdgWTWm[6]);var MAMqWDJK" ascii
    $s19 = "function AKHIhAKuwKp(RGnQg,GtyYNtHlbpaxN,wOLFkkzAkCWt){dlSMhAVOt=RGnQg.split(wOLFkkzAkCWt);WhVVBfuLrQoh = KLVNhMAdjPixeGdgWTWm[1" ascii
    $s20 = "function fI(DMoDuiQjNiUhU){return String.fromCharCode(DMoDuiQjNiUhU);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}