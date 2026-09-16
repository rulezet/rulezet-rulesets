rule sig_20160531_31cce0c14f70b855384da1a737844b47 {
  meta:
    description = "datamaliciousorder - file 20160531_31cce0c14f70b855384da1a737844b47.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff59e17dd0a0773a92623b1f226cac858ea7346510124c47bcb63491433ba1f2"

  strings:
    $s1  = "function SgxiDasXrrIz(QzaDOVVHFPdiaOgcqt,jLPQjxOcVaPOWS){return QzaDOVVHFPdiaOgcqt.charAt(jLPQjxOcVaPOWS);}" fullword ascii
    $s2  = "function roNdGKKGPTMPmR(fnZReZShhTPMP,OxDGiTjz,mNWtMPwIfatkol){bRcieaIucUxvfR=fnZReZShhTPMP.split(mNWtMPwIfatkol);PLGWWSVVyB = c" ascii
    $s3  = "var NxlnrcTHtiupx=function(){return WScript.CreateObject(cwJnHvSCAYhzpOoHobGFRQeN[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" ascii
    $s4  = "function PUskbCFW(rEbzactXzdPXr) {var gebgeYEsCClxpxkA = YqFgdFXj.join(cwJnHvSCAYhzpOoHobGFRQeN[7]);var KTOeNBPfnyiokpoqFvIMyzer" ascii
    $s5  = "function PUskbCFW(rEbzactXzdPXr) {var gebgeYEsCClxpxkA = YqFgdFXj.join(cwJnHvSCAYhzpOoHobGFRQeN[7]);var KTOeNBPfnyiokpoqFvIMyzer" ascii
    $s6  = "function QvYhvSrXQg(fgGnrOhcBKsiKciGOTsSho,eeYSUvSNvhbEqnlYNiykz){return String.fromCharCode(fgGnrOhcBKsiKciGOTsSho,eeYSUvSNvhbE" ascii
    $s7  = "function NuIkmHYJjvojxD(tPkzTutdVjtmQIqbEwpT,nXatiaXRQxnz){return tPkzTutdVjtmQIqbEwpT.indexOf(nXatiaXRQxnz);}" fullword ascii
    $s8  = "fL);} while (wCKFCgeFJMFxjMSzMrQ < rEbzactXzdPXr.length);return XRlyUvcBziYWuzYxHuE;}" fullword ascii
    $s9  = "function SLKjrIYK(HUDrzDtJQIulFAZhLbSjel,DErbtf,AcVyJMPDAdEiJF){return String.fromCharCode(HUDrzDtJQIulFAZhLbSjel,DErbtf,AcVyJMP" ascii
    $s10 = "function tk(FGnkaBF){return String.fromCharCode(FGnkaBF);}" fullword ascii
    $s11 = "yiokpoqFvIMyzer, oTHAiSNRhyzgVt);else XRlyUvcBziYWuzYxHuE += SLKjrIYK(KTOeNBPfnyiokpoqFvIMyzer, oTHAiSNRhyzgVt, mOEmXzNQLVTNcsoI" ascii
    $s12 = "function QvYhvSrXQg(fgGnrOhcBKsiKciGOTsSho,eeYSUvSNvhbEqnlYNiykz){return String.fromCharCode(fgGnrOhcBKsiKciGOTsSho,eeYSUvSNvhbE" ascii
    $s13 = "(mwKkzG,0x1,0x0)}function RqbtviVF(yAwoWh,aAOnhEZzWJ,sePxEXNsYsIuod){var wSoWvPkESZU=yAwoWh.createtextfile(aAOnhEZzWJ,true);wSoW" ascii
    $s14 = "i == 64) XRlyUvcBziYWuzYxHuE += tk(KTOeNBPfnyiokpoqFvIMyzer);else if (LfikRpl == 64) XRlyUvcBziYWuzYxHuE += QvYhvSrXQg(KTOeNBPfn" ascii
    $s15 = "(mwKkzG,0x1,0x0)}function RqbtviVF(yAwoWh,aAOnhEZzWJ,sePxEXNsYsIuod){var wSoWvPkESZU=yAwoWh.createtextfile(aAOnhEZzWJ,true);wSoW" ascii
    $s16 = "function SLKjrIYK(HUDrzDtJQIulFAZhLbSjel,DErbtf,AcVyJMPDAdEiJF){return String.fromCharCode(HUDrzDtJQIulFAZhLbSjel,DErbtf,AcVyJMP" ascii
    $s17 = "function uEIHgNbHaooesy(){return NxlnrcTHtiupx.ExpandEnvironmentStrings(kORLXy())}" fullword ascii
    $s18 = "function kORLXy(){return roNdGKKGPTMPmR(cwJnHvSCAYhzpOoHobGFRQeN[9],[1,5,7],cwJnHvSCAYhzpOoHobGFRQeN[10]);}" fullword ascii
    $s19 = "function roNdGKKGPTMPmR(fnZReZShhTPMP,OxDGiTjz,mNWtMPwIfatkol){bRcieaIucUxvfR=fnZReZShhTPMP.split(mNWtMPwIfatkol);PLGWWSVVyB = c" ascii
    $s20 = "function RdKfoCpEaL(){return roNdGKKGPTMPmR(cwJnHvSCAYhzpOoHobGFRQeN[11],[2,4,8,10],cwJnHvSCAYhzpOoHobGFRQeN[12]);}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}