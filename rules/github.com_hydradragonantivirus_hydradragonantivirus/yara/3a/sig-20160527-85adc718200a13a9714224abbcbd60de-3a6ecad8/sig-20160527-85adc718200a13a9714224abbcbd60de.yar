rule sig_20160527_85adc718200a13a9714224abbcbd60de {
  meta:
    description = "datamaliciousorder - file 20160527_85adc718200a13a9714224abbcbd60de.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "697c1db49ed4694a81612de10c911b803bc8caf904e11ed30e299a5de5ddaa84"

  strings:
    $s1  = "function ZdVuPw(eqtKYGOkjiMeX) {var vVTjPeyeC = oZLfz.join(yTtQuWszhzAdQsWiKtbmlf[6]);var THNDHXdIfuj, DSkwPOLVXLQNKzNyzAbRX, oG" ascii
    $s2  = "function tAPzSZEmJj() {return WScript;}function dKuhldylODB(){return YJDeRgZrzQzEx.ExpandEnvironmentStrings(iluhVYwAyAxsAg())}" fullword ascii
    $s3  = "daOGsbUciaTR & 0xff;if (vTEtihcTIAxoioqvdvwS == 64) jmcTjnBrkIROsruSOo += KY(THNDHXdIfuj);else if (bkyIrCHCbBeKuKPkaRr == 64) jm" ascii
    $s4  = "function ZdVuPw(eqtKYGOkjiMeX) {var vVTjPeyeC = oZLfz.join(yTtQuWszhzAdQsWiKtbmlf[6]);var THNDHXdIfuj, DSkwPOLVXLQNKzNyzAbRX, oG" ascii
    $s5  = "function LMvGHQez(oYKCnSK,gZIcTcIXvAaNFVfN){return oYKCnSK.charAt(gZIcTcIXvAaNFVfN);}" fullword ascii
    $s6  = "function mNIwIpkDIPAFcUBTk(xwjktbLfaRIv,rAXlhDKzsAYJyTS){return xwjktbLfaRIv.indexOf(rAXlhDKzsAYJyTS);}" fullword ascii
    $s7  = "function gndXmUKo(msNJzcguAbtb,xxxkHJlpU) {var HTQlu=[yTtQuWszhzAdQsWiKtbmlf[15]];msNJzcguAbtb[HTQlu[0]](xxxkHJlpU,0x1,0x0)}" fullword ascii
    $s8  = "var YJDeRgZrzQzEx=function(){return tAPzSZEmJj().CreateObject(yTtQuWszhzAdQsWiKtbmlf[1].replace(new RegExp(\"u\",\"g\"),\"\"));}" ascii
    $s9  = "function eskHwWosafmh(sSfqviXqrcndYa,anyajEsQ){return String.fromCharCode(sSfqviXqrcndYa,anyajEsQ);}" fullword ascii
    $s10 = "function KY(xlKzmvmHanaTydmzFm){return String.fromCharCode(xlKzmvmHanaTydmzFm);}" fullword ascii
    $s11 = "NKzNyzAbRX, oGvAJRtblUuBdOvZaQ);} while (VOhfjvAqTatyaHZ < eqtKYGOkjiMeX.length);return jmcTjnBrkIROsruSOo;}" fullword ascii
    $s12 = "XEK]];}return SPDeRtZMHN.substring(3,SPDeRtZMHN.length);}" fullword ascii
    $s13 = "var PUUWTcR = WhGURfXx.createtextfile(YJDeRgZrzQzEx.ExpandEnvironmentStrings(yTtQuWszhzAdQsWiKtbmlf[2]+yTtQuWszhzAdQsWiKtbmlf[3]" ascii
    $s14 = "var WhGURfXx=function(){return new ActiveXObject(yTtQuWszhzAdQsWiKtbmlf[0]);}();" fullword ascii
    $s15 = "cTjnBrkIROsruSOo += eskHwWosafmh(THNDHXdIfuj, DSkwPOLVXLQNKzNyzAbRX);else jmcTjnBrkIROsruSOo += vjQFDXx(THNDHXdIfuj, DSkwPOLVXLQ" ascii
    $s16 = "function vjQFDXx(jqhTFjvozyqN,WAfmuF,SimRzKWCTmmT){return String.fromCharCode(jqhTFjvozyqN,WAfmuF,SimRzKWCTmmT);}" fullword ascii
    $s17 = ")+String.fromCharCode(92)+yTtQuWszhzAdQsWiKtbmlf[4],true);" fullword ascii
    $s18 = "function CjMoCnvqKI(){return chfVhCaf(yTtQuWszhzAdQsWiKtbmlf[12],[0,3,6],yTtQuWszhzAdQsWiKtbmlf[13]);}" fullword ascii
    $s19 = "function PNXjsH(){return chfVhCaf(yTtQuWszhzAdQsWiKtbmlf[10],[2,4,8,10],yTtQuWszhzAdQsWiKtbmlf[11]);}" fullword ascii
    $s20 = "function chfVhCaf(nkYbpGqjkhsn,rRusXXqdYfmg,SqdQYG){DEwztElVeLvE=nkYbpGqjkhsn.split(SqdQYG);SPDeRtZMHN = yTtQuWszhzAdQsWiKtbmlf[" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}