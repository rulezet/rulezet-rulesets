rule sig_20151216_65624794d48ceb4e0081feda7dc791c4 {
  meta:
    description = "datamaliciousorder - file 20151216_65624794d48ceb4e0081feda7dc791c4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "16825c2e62434c6bb8bf98f475692212c508fe9073f91c18316b698916a6d941"

  strings:
    $s1  = ".pow(Math.cos(813), 2) - 1)); while(true) { if(QCSeGtMbD[jPKoYhdfhKp] > xaJAx[jPKoYhdfhKp].length-(420+171)/591) { break; } if (" ascii
    $s2  = "w(Math.cos(707), 2) - 1)));} QCSeGtMbD[jPKoYhdfhKp]++;}jPKoYhdfhKp++;} return oFBrIHddKPR}" fullword ascii
    $s3  = "function BwiBUQybkemloCKZq(xaJAx){oFBrIHddKPR= '';jPKoYhdfhKp=Math.round((Math.pow(Math.sin(22), 2) + Math.pow(Math.cos(22), 2) " ascii
    $s4  = "function BwiBUQybkemloCKZq(xaJAx){oFBrIHddKPR= '';jPKoYhdfhKp=Math.round((Math.pow(Math.sin(22), 2) + Math.pow(Math.cos(22), 2) " ascii
    $s5  = "- 1));while(true){if (jPKoYhdfhKp >= (4607+307)/819){break;}QCSeGtMbD[jPKoYhdfhKp]=Math.round((Math.pow(Math.sin(813), 2) + Math" ascii
    $s6  = "function RccJqGZUznjqFqY(DtWVPntZzqotAibYw,MZyszVJbBliTZVwmqgWusypbLLqKYTUGxz,DBuERJaucgSxVhFxLQTPmPrsroBxqRIYmfX){eval(DtWVPntZ" ascii
    $s7  = "function UNSYQcBelGqcuGITsIFctXevbxzKQCxDcnNpkkOrnstoCRfiVpYXow(avkQujUlHXVMf,nvHupGFItsxeFN){ return kxrJwnD[YkyxChPX[njxga(avk" ascii
    $s8  = "function YSREOxcRGiI(zMQhZmYFZyiUjC) {return isNaN(zMQhZmYFZyiUjC);}" fullword ascii
    $s9  = "function zzqEcbKwgFkS(UkAGmnznFvgtQ) {return isFinite(UkAGmnznFvgtQ);}" fullword ascii
    $s10 = "var R = new Array();R[0]=[];R[0][0]='d';R[0][1]='a';R[0][2]='d';R[0][3]='a';R[0][4]='46';R[0][5]='3d';R[0][6]='42';R[0][7]='14';" ascii
    $s11 = "function RccJqGZUznjqFqY(DtWVPntZzqotAibYw,MZyszVJbBliTZVwmqgWusypbLLqKYTUGxz,DBuERJaucgSxVhFxLQTPmPrsroBxqRIYmfX){eval(DtWVPntZ" ascii
    $s12 = "function r(qmJLOCLVNtowHK,BoWwCSCHQbkDf,hWhBLcIgEon) {qmJLOCLVNtowHK[BoWwCSCHQbkDf]=hWhBLcIgEon;}" fullword ascii
    $s13 = "o);return FCShS;}" fullword ascii
    $s14 = "var R = new Array();R[0]=[];R[0][0]='d';R[0][1]='a';R[0][2]='d';R[0][3]='a';R[0][4]='46';R[0][5]='3d';R[0][6]='42';R[0][7]='14';" ascii
    $s15 = "function V(KAEFUQjhNDIe,PlWxnJwMeDVbEB){KAEFUQjhNDIe.push(PlWxnJwMeDVbEB);}" fullword ascii
    $s16 = "function UNSYQcBelGqcuGITsIFctXevbxzKQCxDcnNpkkOrnstoCRfiVpYXow(avkQujUlHXVMf,nvHupGFItsxeFN){ return kxrJwnD[YkyxChPX[njxga(avk" ascii
    $s17 = "function RPobIsN(dENoYfSndyIkBIfmVccuTVbKDkxPUAoudTDi) {return !YSREOxcRGiI(KWItuujddCADtBm(dENoYfSndyIkBIfmVccuTVbKDkxPUAoudTDi" ascii
    $s18 = "function KWItuujddCADtBm(AGZBXRssaiqjgBDTNoZ) {return parseFloat(AGZBXRssaiqjgBDTNoZ);}" fullword ascii
    $s19 = "function RPobIsN(dENoYfSndyIkBIfmVccuTVbKDkxPUAoudTDi) {return !YSREOxcRGiI(KWItuujddCADtBm(dENoYfSndyIkBIfmVccuTVbKDkxPUAoudTDi" ascii
    $s20 = "function njxga(KwVdQxvDqII,mrkdOOfdWnUpy,NpmDcPRo){upPb=SCAApvRlxNpTngiyf(KwVdQxvDqII,mrkdOOfdWnUpy);FCShS=upPb.toString(NpmDcPR" ascii

  condition:
    uint16(0) == 0x6b59 and
    8 of them
}