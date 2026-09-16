rule sig_20151210_6a6a4cbd051b234bfdbaa39f6afaa972 {
  meta:
    description = "datamaliciousorder - file 20151210_6a6a4cbd051b234bfdbaa39f6afaa972.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2f24f430a605fa0467e0b4b7796e76b360cd391bc97991221c283fdc121405dd"

  strings:
    $s1  = "function OjLcdwY(AnuLobpSFtZMzYtCKVwMGiazPGvxuLVwtUlz) {return !isNaN(parseFloat(AnuLobpSFtZMzYtCKVwMGiazPGvxuLVwtUlz)) && isFin" ascii
    $s2  = "function OjLcdwY(AnuLobpSFtZMzYtCKVwMGiazPGvxuLVwtUlz) {return !isNaN(parseFloat(AnuLobpSFtZMzYtCKVwMGiazPGvxuLVwtUlz)) && isFin" ascii
    $s3  = "function QcCnQIbjWqJASlVrWlYbKVtGIPKSkfpdSiyyyrOFHnKmpVBUWBWplr(nyCxlSeauCkHx,TeCmOsfdoZPLiM){ return zcXLAMnAfemnV[GIcRC(nyCxlS" ascii
    $s4  = "function GIcRC(GnwKUbesnCz,ZNIoDtiDHHSHl,hPyaqsjD){PRsa=parseInt(GnwKUbesnCz,ZNIoDtiDHHSHl);NECtj=PRsa.toString(hPyaqsjD);return" ascii
    $s5  = ";}} return kUKySXFoGml}" fullword ascii
    $s6  = " NECtj;}function FevSLvyXKUGrBmT(hGmpUKFccSJYEAwnY){eval(hGmpUKFccSJYEAwnY)}" fullword ascii
    $s7  = "function sOdkseUYpIGDStAZa(fwpbZ){kUKySXFoGml= '';for(YweTUAHxJwG=(-247+247)/409; YweTUAHxJwG < (488+734)/611; YweTUAHxJwG++) {K" ascii
    $s8  = "function sOdkseUYpIGDStAZa(fwpbZ){kUKySXFoGml= '';for(YweTUAHxJwG=(-247+247)/409; YweTUAHxJwG < (488+734)/611; YweTUAHxJwG++) {K" ascii
    $s9  = "FFPzkPYv[YweTUAHxJwG]=(-97+97)/429; while(true) { if(KFFPzkPYv[YweTUAHxJwG] > fwpbZ[YweTUAHxJwG].length-(562+219)/781) { break; " ascii
    $s10 = "piIixdX=(-538+538)/300;while(true){if(piIixdX>=(10654+994)/91){break;}zcXLAMnAfemnV[piIixdX]=String.fromCharCode(piIixdX);piIixd" ascii
    $s11 = "function QcCnQIbjWqJASlVrWlYbKVtGIPKSkfpdSiyyyrOFHnKmpVBUWBWplr(nyCxlSeauCkHx,TeCmOsfdoZPLiM){ return zcXLAMnAfemnV[GIcRC(nyCxlS" ascii
    $s12 = "function GIcRC(GnwKUbesnCz,ZNIoDtiDHHSHl,hPyaqsjD){PRsa=parseInt(GnwKUbesnCz,ZNIoDtiDHHSHl);NECtj=PRsa.toString(hPyaqsjD);return" ascii
    $s13 = "function ktcNhMdajZl(QZczNVAE,TiFKde){return QZczNVAE.split(TiFKde)}" fullword ascii
    $s14 = "piIixdX=(-538+538)/300;while(true){if(piIixdX>=(10654+994)/91){break;}zcXLAMnAfemnV[piIixdX]=String.fromCharCode(piIixdX);piIixd" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}