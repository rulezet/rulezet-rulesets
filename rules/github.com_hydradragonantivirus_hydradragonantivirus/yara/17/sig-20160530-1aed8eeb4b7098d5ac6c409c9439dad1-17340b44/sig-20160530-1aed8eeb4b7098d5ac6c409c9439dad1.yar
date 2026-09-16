rule sig_20160530_1aed8eeb4b7098d5ac6c409c9439dad1 {
  meta:
    description = "datamaliciousorder - file 20160530_1aed8eeb4b7098d5ac6c409c9439dad1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "089f52dc7fe6335058da1bf4daf02aa5b014803551276096b2ca730fab8b56cb"

  strings:
    $s1  = "var ygkTRokXnuJHOC=function(){return WScript.CreateObject(rglfHKbiemneIBvnxtaPcK[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function LSeBPMAkOliFK(ZcwXVDvFTfQXiZXHgTttx,UrJRfwtGvnEwDs){return ZcwXVDvFTfQXiZXHgTttx.charAt(UrJRfwtGvnEwDs);}" fullword ascii
    $s3  = "function xijjnIz(){return PoMrVReg(rglfHKbiemneIBvnxtaPcK[9],[1,5,7],rglfHKbiemneIBvnxtaPcK[10]);}" fullword ascii
    $s4  = "function cE(csfkBdOI){return String.fromCharCode(csfkBdOI);}" fullword ascii
    $s5  = "function RkxDwHld(eNwieyqPveIlC) {var tTiUVilv = HvYKZYFEqAgxmYfuZ.join(rglfHKbiemneIBvnxtaPcK[7]);var yckLAVxjwFYJ, XWEqAOWIpY," ascii
    $s6  = "function MtUQfMPw(){return PoMrVReg(rglfHKbiemneIBvnxtaPcK[11],[2,4,8,10],rglfHKbiemneIBvnxtaPcK[12]);}" fullword ascii
    $s7  = "pDs == 64) XuhyJEC += cE(yckLAVxjwFYJ);else if (lgGhhKxoYQSsf == 64) XuhyJEC += dQnrwmPjwpYWWHICZzcQIk(yckLAVxjwFYJ, XWEqAOWIpY)" ascii
    $s8  = "function pbWppaKb(){return PoMrVReg(rglfHKbiemneIBvnxtaPcK[13],[0,3,6],rglfHKbiemneIBvnxtaPcK[14]);}" fullword ascii
    $s9  = "function RkxDwHld(eNwieyqPveIlC) {var tTiUVilv = HvYKZYFEqAgxmYfuZ.join(rglfHKbiemneIBvnxtaPcK[7]);var yckLAVxjwFYJ, XWEqAOWIpY," ascii
    $s10 = "var NjcEZ=function(){return new ActiveXObject(rglfHKbiemneIBvnxtaPcK[1]);}();" fullword ascii
    $s11 = "function dQnrwmPjwpYWWHICZzcQIk(DyjaSBMLRe,JONatFWr){return String.fromCharCode(DyjaSBMLRe,JONatFWr);}" fullword ascii
    $s12 = "function jhOHmAOAxoCh(){return ygkTRokXnuJHOC.ExpandEnvironmentStrings(xijjnIz())}" fullword ascii
    $s13 = "function PoMrVReg(CLGzx,ddPfUqMePFoy,AZDTrPWKgBi){KFTulIa=CLGzx.split(AZDTrPWKgBi);XpLtaHbjMFIx = rglfHKbiemneIBvnxtaPcK[0];for(" ascii
    $s14 = "function aCovFYCBUY(uSNMPZiHIZwQanLNQuWqzKzL,fBDwptwONbtaQQUftUaUh){return uSNMPZiHIZwQanLNQuWqzKzL.indexOf(fBDwptwONbtaQQUftUaU" ascii
    $s15 = "var yhiJjsBx = NjcEZ.createtextfile(ygkTRokXnuJHOC.ExpandEnvironmentStrings(rglfHKbiemneIBvnxtaPcK[3]+rglfHKbiemneIBvnxtaPcK[4])" ascii
    $s16 = "function JAKoICgbJxivtHqatoQbM(FKQwPamkkgopon,pFRVWCY,NeoUTLFfrZraPSfnGGZJSD){return String.fromCharCode(FKQwPamkkgopon,pFRVWCY," ascii
    $s17 = "function NRpSd(AZGuDVQOPdJTV,FNKiRWp) {var AwlazTYnyTmf=[rglfHKbiemneIBvnxtaPcK[15]];AZGuDVQOPdJTV[AwlazTYnyTmf[0]]" fullword ascii
    $s18 = "function aCovFYCBUY(uSNMPZiHIZwQanLNQuWqzKzL,fBDwptwONbtaQQUftUaUh){return uSNMPZiHIZwQanLNQuWqzKzL.indexOf(fBDwptwONbtaQQUftUaU" ascii
    $s19 = "+String.fromCharCode(92)+rglfHKbiemneIBvnxtaPcK[5],true);" fullword ascii
    $s20 = "function PoMrVReg(CLGzx,ddPfUqMePFoy,AZDTrPWKgBi){KFTulIa=CLGzx.split(AZDTrPWKgBi);XpLtaHbjMFIx = rglfHKbiemneIBvnxtaPcK[0];for(" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}