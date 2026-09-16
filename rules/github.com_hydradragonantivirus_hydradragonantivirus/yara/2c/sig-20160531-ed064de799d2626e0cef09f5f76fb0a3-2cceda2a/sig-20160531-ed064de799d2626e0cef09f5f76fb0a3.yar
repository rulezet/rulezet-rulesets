rule sig_20160531_ed064de799d2626e0cef09f5f76fb0a3 {
  meta:
    description = "datamaliciousorder - file 20160531_ed064de799d2626e0cef09f5f76fb0a3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b2ff2a514da42ba1d18bfd8e1c3b3d7b76ac62b6f305f722023217c3c9e4aa9"

  strings:
    $s1  = "var lzWSYTmnGEXe=function(){return WScript.CreateObject(NdGyEtXermWNAsVVZeu[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function JlUlWXOyHJSzeYpzFMLb(oXSmCKhINoqCAOoRpjSoVn,iVDhZDmDeNdzSY){return oXSmCKhINoqCAOoRpjSoVn.charAt(iVDhZDmDeNdzSY);}" fullword ascii
    $s3  = "(oGHuxJZvqYlRzf,0x1,0x0)}function qcsbpVxPwPB(CJqgWOPGdWNS,FRpHpBeHoL,LcJmZHYfr){var DAPAab=CJqgWOPGdWNS.createtextfile(FRpHpBeH" ascii
    $s4  = "I += a(EMyZhVTuExfEmj);else if (LntngxptaAkmjrGkDUay == 64) pabaKpI += UvLBxSpUvHurlyzYDwBUH(EMyZhVTuExfEmj, TOpCUqlvoMUkay);els" ascii
    $s5  = "function a(ptuSDrlfljjoTAbxccPY){return String.fromCharCode(ptuSDrlfljjoTAbxccPY);}" fullword ascii
    $s6  = "function nmgBB(){return lzWSYTmnGEXe.ExpandEnvironmentStrings(kcWETaZEUcCM())}" fullword ascii
    $s7  = "(oGHuxJZvqYlRzf,0x1,0x0)}function qcsbpVxPwPB(CJqgWOPGdWNS,FRpHpBeHoL,LcJmZHYfr){var DAPAab=CJqgWOPGdWNS.createtextfile(FRpHpBeH" ascii
    $s8  = "var gopWFf=function(){return new ActiveXObject(NdGyEtXermWNAsVVZeu[1]);}();" fullword ascii
    $s9  = "function AtRzIgjKVplFm(viWTcHIdnARij) {var ImEvoWORfsnTWAqV = gENKSDMRSvfBtgfkMUbzk.join(NdGyEtXermWNAsVVZeu[7]);var EMyZhVTuExf" ascii
    $s10 = "function kMFGcRoZmgGggC(ctQiedlFaW,oGHuxJZvqYlRzf) {var ZGeHPLUOT=[NdGyEtXermWNAsVVZeu[15]];ctQiedlFaW[ZGeHPLUOT[0]]" fullword ascii
    $s11 = "function gamhsOJaKWT(){return EUYGjpD(NdGyEtXermWNAsVVZeu[13],[0,3,6],NdGyEtXermWNAsVVZeu[14]);}" fullword ascii
    $s12 = "function xMwtvHTjptjiaVpLt(XjtKsHzKXdjzVPGWjW,kuqLEWAiXIe,XWVtpAqFqohLNLzudKAgkzbZ){return String.fromCharCode(XjtKsHzKXdjzVPGWj" ascii
    $s13 = "function DSpCTIDLShhcEhOPfLUTeP(MbyDTPkVBaDmLmV,VczrKbawsLKfe){return MbyDTPkVBaDmLmV.indexOf(VczrKbawsLKfe);}" fullword ascii
    $s14 = "function uZqxjyqXyKlJU(){return EUYGjpD(NdGyEtXermWNAsVVZeu[11],[2,4,8,10],NdGyEtXermWNAsVVZeu[12]);}" fullword ascii
    $s15 = "oL,true);DAPAab.WriteLine(LcJmZHYfr);DAPAab.Close();}" fullword ascii
    $s16 = "function kcWETaZEUcCM(){return EUYGjpD(NdGyEtXermWNAsVVZeu[9],[1,5,7],NdGyEtXermWNAsVVZeu[10]);}" fullword ascii
    $s17 = "function UvLBxSpUvHurlyzYDwBUH(yQusWJrwO,gXHyXYjAlIRSymoOde){return String.fromCharCode(yQusWJrwO,gXHyXYjAlIRSymoOde);}" fullword ascii
    $s18 = "function xMwtvHTjptjiaVpLt(XjtKsHzKXdjzVPGWjW,kuqLEWAiXIe,XWVtpAqFqohLNLzudKAgkzbZ){return String.fromCharCode(XjtKsHzKXdjzVPGWj" ascii
    $s19 = "function EUYGjpD(nvkeMWpOkTJX,PVGhggNDKRqDRi,inyinCYZd){enqEaIy=nvkeMWpOkTJX.split(inyinCYZd);CAvpEbopE = NdGyEtXermWNAsVVZeu[0]" ascii
    $s20 = ";for(rjnduhetftXW=0;rjnduhetftXW<PVGhggNDKRqDRi.length;rjnduhetftXW++) {CAvpEbopE+=enqEaIy[PVGhggNDKRqDRi[rjnduhetftXW]];}return" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}