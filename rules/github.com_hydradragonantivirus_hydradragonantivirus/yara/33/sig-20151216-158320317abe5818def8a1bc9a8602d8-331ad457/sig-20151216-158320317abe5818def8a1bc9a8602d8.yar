rule sig_20151216_158320317abe5818def8a1bc9a8602d8 {
  meta:
    description = "datamaliciousorder - file 20151216_158320317abe5818def8a1bc9a8602d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bef869dee77f6344a423d95c3eb5d3f4b34b728d49a47dcaffe17f30f403e1c9"

  strings:
    $s1  = "Math.cos(516), 2) - 1)));} vxOJZuQhz[HNkmsLwzCSN]++;}HNkmsLwzCSN++;} return BuSBIkLxKeM}" fullword ascii
    $s2  = "th.pow(Math.cos(521), 2) - 1)); while(true) { if(vxOJZuQhz[HNkmsLwzCSN] > VajAy[HNkmsLwzCSN].length-(92+290)/382) { break; } if " ascii
    $s3  = ") - 1));while(true){if (HNkmsLwzCSN >= (1136+166)/217){break;}vxOJZuQhz[HNkmsLwzCSN]=Math.round((Math.pow(Math.sin(521), 2) + Ma" ascii
    $s4  = "function HxJrItIqDexZEzTKy(VajAy){BuSBIkLxKeM= '';HNkmsLwzCSN=Math.round((Math.pow(Math.sin(843), 2) + Math.pow(Math.cos(843), 2" ascii
    $s5  = "function HxJrItIqDexZEzTKy(VajAy){BuSBIkLxKeM= '';HNkmsLwzCSN=Math.round((Math.pow(Math.sin(843), 2) + Math.pow(Math.cos(843), 2" ascii
    $s6  = "function kxbLgQo(KectnsWevZLbOKUgCEISYACECtFOcTRHKmyf) {return !AxliRZjrOON(fBCMgLsCUXWGKxt(KectnsWevZLbOKUgCEISYACECtFOcTRHKmyf" ascii
    $s7  = ",'w','v','*',')','t','u','=','W','J','X','E','b','%',' ','O','D','a','-','Y','.','n','X','Z','J','f','Y','W','/','[','!',String." ascii
    $s8  = "o);return ZJrjV;}" fullword ascii
    $s9  = "function rQVAKIQnPRKN(WwjROKRtAnvNi) {return isFinite(WwjROKRtAnvNi);}" fullword ascii
    $s10 = "function R(CijGMJkiwFNvZO,TeehpbhMQcqhe,NlGYRRFrdXC) {CijGMJkiwFNvZO[TeehpbhMQcqhe]=NlGYRRFrdXC;}" fullword ascii
    $s11 = "var j = new Array();j[0]=[];j[0][0]='d';j[0][1]='a';j[0][2]='d';j[0][3]='a';j[0][4]='46';j[0][5]='3d';j[0][6]='42';j[0][7]='14';" ascii
    $s12 = "function AxliRZjrOON(grDiMGdtQzZvOv) {return isNaN(grDiMGdtQzZvOv);}" fullword ascii
    $s13 = "function JOQHe(TgIKPlzHbiM,olnIJniOGfSCR,xajPTRlo){vnwB=qVKUrqHeMUGciuyoD(TgIKPlzHbiM,olnIJniOGfSCR);ZJrjV=vnwB.toString(xajPTRl" ascii
    $s14 = "function qVKUrqHeMUGciuyoD(nQXRoOzzdg,SEXFuMNLEu) {return parseInt(nQXRoOzzdg,SEXFuMNLEu);}" fullword ascii
    $s15 = "function JOQHe(TgIKPlzHbiM,olnIJniOGfSCR,xajPTRlo){vnwB=qVKUrqHeMUGciuyoD(TgIKPlzHbiM,olnIJniOGfSCR);ZJrjV=vnwB.toString(xajPTRl" ascii
    $s16 = "function fBCMgLsCUXWGKxt(gJFeOIAFqOVfCWtQUrI) {return parseFloat(gJFeOIAFqOVfCWtQUrI);}" fullword ascii
    $s17 = "function g(uHNiylkRfGJi,vOozKwkbizosiw){uHNiylkRfGJi.push(vOozKwkbizosiw);}" fullword ascii
    $s18 = "function kxbLgQo(KectnsWevZLbOKUgCEISYACECtFOcTRHKmyf) {return !AxliRZjrOON(fBCMgLsCUXWGKxt(KectnsWevZLbOKUgCEISYACECtFOcTRHKmyf" ascii
    $s19 = "function EnlZgcHAYaOcaMLXwRaDCtRViwfJlcAlLCBvFwBIXWSOObKwScPTdA(BejaiSGyMnsVc,gRbkXbeyWJQnMp){ return NCHRDlT[imWiVALn[JOQHe(Bej" ascii
    $s20 = "function EnlZgcHAYaOcaMLXwRaDCtRViwfJlcAlLCBvFwBIXWSOObKwScPTdA(BejaiSGyMnsVc,gRbkXbeyWJQnMp){ return NCHRDlT[imWiVALn[JOQHe(Bej" ascii

  condition:
    uint16(0) == 0x6d69 and
    8 of them
}