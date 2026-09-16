rule sig_20160530_35c4e53d991fa68bd4ef572c82227a39 {
  meta:
    description = "datamaliciousorder - file 20160530_35c4e53d991fa68bd4ef572c82227a39.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bef3a3995148133b2631c5560554bf5077ae70be8df2fa08958390a6276535ae"

  strings:
    $s1  = "var tupvPQzLE=function(){return WScript.CreateObject(wGKimvPpzRHm[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function FtJUVFdF(tVtbxKgCjNQXd,jiBWXsrJ){return tVtbxKgCjNQXd.charAt(jiBWXsrJ);}" fullword ascii
    $s3  = "function KtJgjPogvSSOSy(tEHdLrNMXPzXph,KVkJy,wnREiDTjfS){mOQyrlY=tEHdLrNMXPzXph.split(wnREiDTjfS);kziqdfIpTR = wGKimvPpzRHm[0];f" ascii
    $s4  = "function lGqrla(xaBpm,cLfFJsJg) {var inXQaafcbw=[wGKimvPpzRHm[15]];xaBpm[inXQaafcbw[0]]" fullword ascii
    $s5  = "ROhiSmNP += zIRwmaDGMWZyrIQpBEv(ktBWGH, IiFwRWGb, SPhTuWswwNWWWB);} while (GsosCccOblHdGLDM < NXfMCnZGwUxhE.length);return ROhiS" ascii
    $s6  = "wGKimvPpzRHm[5],true);" fullword ascii
    $s7  = "function cXmrbHGmEjyYSm(){return tupvPQzLE.ExpandEnvironmentStrings(otevHds())}" fullword ascii
    $s8  = "function lylYC(NXfMCnZGwUxhE) {var HCYUbIBmwZzgT = QQwBokpaXcwqcEADgd.join(wGKimvPpzRHm[7]);var ktBWGH, IiFwRWGb, SPhTuWswwNWWWB" ascii
    $s9  = "function otevHds(){return KtJgjPogvSSOSy(wGKimvPpzRHm[9],[1,5,7],wGKimvPpzRHm[10]);}" fullword ascii
    $s10 = "or(XTMeWUqEumaH=0;XTMeWUqEumaH<KVkJy.length;XTMeWUqEumaH++) {kziqdfIpTR+=mOQyrlY[KVkJy[XTMeWUqEumaH]];}return kziqdfIpTR.substri" ascii
    $s11 = "var sUSIFjgE = zcDZg.createtextfile(tupvPQzLE.ExpandEnvironmentStrings(wGKimvPpzRHm[3]+wGKimvPpzRHm[4])+String.fromCharCode(92)+" ascii
    $s12 = "function dOzleJpLXPEizeiSJiAKvej(laFaKdCRhsPctyPKIuJjYDhV,lWqfibRE){return String.fromCharCode(laFaKdCRhsPctyPKIuJjYDhV,lWqfibRE" ascii
    $s13 = "WmvCCEGJpY == 64) ROhiSmNP += n(ktBWGH);else if (qzcpEPuCVbPn == 64) ROhiSmNP += dOzleJpLXPEizeiSJiAKvej(ktBWGH, IiFwRWGb);else " ascii
    $s14 = "function ZFIoIcpEUTz(){return KtJgjPogvSSOSy(wGKimvPpzRHm[11],[2,4,8,10],wGKimvPpzRHm[12]);}" fullword ascii
    $s15 = "push(\"D\");QQwBokpaXcwqcEADgd.push(\"3\");QQwBokpaXcwqcEADgd.push(\"E\");QQwBokpaXcwqcEADgd.push(\"F\");QQwBokpaXcwqcEADgd.push" ascii
    $s16 = "function zIRwmaDGMWZyrIQpBEv(QpxjKsTbo,rgJnidPMiyVHzAnjndDm,URHmPLgbqDKgUOWzztYVs){return String.fromCharCode(QpxjKsTbo,rgJnidPM" ascii
    $s17 = "function zIRwmaDGMWZyrIQpBEv(QpxjKsTbo,rgJnidPMiyVHzAnjndDm,URHmPLgbqDKgUOWzztYVs){return String.fromCharCode(QpxjKsTbo,rgJnidPM" ascii
    $s18 = "var zcDZg=function(){return new ActiveXObject(wGKimvPpzRHm[1]);}();" fullword ascii
    $s19 = "function n(NJMrdNBvovCHiooOuK){return String.fromCharCode(NJMrdNBvovCHiooOuK);}" fullword ascii
    $s20 = "function KtJgjPogvSSOSy(tEHdLrNMXPzXph,KVkJy,wnREiDTjfS){mOQyrlY=tEHdLrNMXPzXph.split(wnREiDTjfS);kziqdfIpTR = wGKimvPpzRHm[0];f" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}