rule sig_20151217_c1de7f210a45a2858b3c3aa2f3916f5a {
  meta:
    description = "datamaliciousorder - file 20151217_c1de7f210a45a2858b3c3aa2f3916f5a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d39560a85a75a9d66d9de50a1c49c4036d2445f992bfb7144795543e558b17f"

  strings:
    $s1  = "th.pow(Math.cos(638), 2) - 1)); while(true) { if(aQXOwQwwN[JlTDKTpjknI] > PwMkm[JlTDKTpjknI].length-(-708+875)/167) { break; } i" ascii
    $s2  = ") - 1));while(true){if (JlTDKTpjknI >= (1641+783)/404){break;}aQXOwQwwN[JlTDKTpjknI]=Math.round((Math.pow(Math.sin(638), 2) + Ma" ascii
    $s3  = ".pow(Math.cos(163), 2) - 1)));} aQXOwQwwN[JlTDKTpjknI]++;}JlTDKTpjknI++;} return iSsqSablnZR}" fullword ascii
    $s4  = "function CkYAKjCMOwnaGgAcB(PwMkm){iSsqSablnZR= '';JlTDKTpjknI=Math.round((Math.pow(Math.sin(705), 2) + Math.pow(Math.cos(705), 2" ascii
    $s5  = "mXHbJBxSREGwRftikzbtIQzSlgnTehmMVTvi([PwMkm[JlTDKTpjknI][aQXOwQwwN[JlTDKTpjknI]]], Math.round((Math.pow(Math.sin(163), 2) + Math" ascii
    $s6  = "function CkYAKjCMOwnaGgAcB(PwMkm){iSsqSablnZR= '';JlTDKTpjknI=Math.round((Math.pow(Math.sin(705), 2) + Math.pow(Math.cos(705), 2" ascii
    $s7  = "function Uvhokhf(DsEwFgZIXtPmbIeogfZgykEXzGfZbqsETZmT) {return !JpeANkNRlRi(OChqTIqzCblVNfj(DsEwFgZIXtPmbIeogfZgykEXzGfZbqsETZmT" ascii
    $s8  = "var M = new Array();M[0]=[];M[0][0]='d';M[0][1]='a';M[0][2]='d';M[0][3]='a';M[0][4]='46';M[0][5]='3d';M[0][6]='42';M[0][7]='14';" ascii
    $s9  = "function LDNBw(ysXPuOndjoW,mIOxXzyGYozos,mCsXowZy){krwb=KXGMNLBLBBzLJcQYF(ysXPuOndjoW,mIOxXzyGYozos);nLQCG=krwb.toString(mCsXowZ" ascii
    $s10 = "function KXGMNLBLBBzLJcQYF(GvLAIPagqy,lFJYSRqLpl) {return parseInt(GvLAIPagqy,lFJYSRqLpl);}" fullword ascii
    $s11 = "function Uvhokhf(DsEwFgZIXtPmbIeogfZgykEXzGfZbqsETZmT) {return !JpeANkNRlRi(OChqTIqzCblVNfj(DsEwFgZIXtPmbIeogfZgykEXzGfZbqsETZmT" ascii
    $s12 = "function LDNBw(ysXPuOndjoW,mIOxXzyGYozos,mCsXowZy){krwb=KXGMNLBLBBzLJcQYF(ysXPuOndjoW,mIOxXzyGYozos);nLQCG=krwb.toString(mCsXowZ" ascii
    $s13 = "function JpeANkNRlRi(IxpBnxOYYlpWIP) {return isNaN(IxpBnxOYYlpWIP);}" fullword ascii
    $s14 = "function XpLtnBXlsAYsPqzdJimXHbJBxSREGwRftikzbtIQzSlgnTehmMVTvi(RxgSTeRBDKWJA,HiozepojItHLXn){ return YicEgQI[yyvdDALP[LDNBw(Rxg" ascii
    $s15 = "var M = new Array();M[0]=[];M[0][0]='d';M[0][1]='a';M[0][2]='d';M[0][3]='a';M[0][4]='46';M[0][5]='3d';M[0][6]='42';M[0][7]='14';" ascii
    $s16 = "function h(YAPTTjYqLBRo,AGjGisrwjcvASv){YAPTTjYqLBRo.push(AGjGisrwjcvASv);}" fullword ascii
    $s17 = "function xDKOizTpVQAdPJP(wjqLNcTYIYwIwCBAh,ieeeqRWUiyCBXHKIOuALcqTOdlISQTkiuU,DDepoZXqscEJKiqLDDhwbRtLvZZdURqwqSi){eval(wjqLNcTY" ascii
    $s18 = "function xDKOizTpVQAdPJP(wjqLNcTYIYwIwCBAh,ieeeqRWUiyCBXHKIOuALcqTOdlISQTkiuU,DDepoZXqscEJKiqLDDhwbRtLvZZdURqwqSi){eval(wjqLNcTY" ascii
    $s19 = "function OChqTIqzCblVNfj(RHZZFkgYzpXmQlTGNfL) {return parseFloat(RHZZFkgYzpXmQlTGNfL);}" fullword ascii
    $s20 = "function ajeLSuqRpxLo(vwPSWxuOyNQsM) {return isFinite(vwPSWxuOyNQsM);}" fullword ascii

  condition:
    uint16(0) == 0x7979 and
    8 of them
}