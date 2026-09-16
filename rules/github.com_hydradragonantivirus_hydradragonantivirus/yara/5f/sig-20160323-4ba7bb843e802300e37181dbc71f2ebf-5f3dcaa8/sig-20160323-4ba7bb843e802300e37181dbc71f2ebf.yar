rule sig_20160323_4ba7bb843e802300e37181dbc71f2ebf {
  meta:
    description = "datamaliciousorder - file 20160323_4ba7bb843e802300e37181dbc71f2ebf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0cf8b3f35f5390b44d30378523748424309d84d50fdefb3c40c171c064ed8b8b"

  strings:
    $s1  = "return WScript.CreateObject(cnvXx);" fullword ascii
    $s2  = "function BAmPlogZ(mwf) {" fullword ascii
    $s3  = "var ap = true  , IOBj = oaZ[7] + oaZ[9] + oaZ[11];" fullword ascii
    $s4  = "return WQGhjtQ[0] + WQGhjtQ[2] + WQGhjtQ[4] + \".F\" + WQGhjtQ[7] + WQGhjtQ[9] + WQGhjtQ[12] + WQGhjtQ[14];" fullword ascii
    $s5  = "var oaZ = (\"2.XMLHTTP QTnxHaI oKKfO XML ream St yIUuOQhw AD otwpZjf O CNnz D\").split(\" \");" fullword ascii
    $s6  = "bzBP.open(DdTUS,aDRfN,false);" fullword ascii
    $s7  = "var WQGhjtQ = wbbLV(rWVCQvdCTG+\" \"+\"System uX aqgHI Obj lYeptp ect GqXhlcR Ezlux\", \" \");" fullword ascii
    $s8  = "function ScFl(RjaTb,FxLAD) {" fullword ascii
    $s9  = "if(l>=r.length) {break;}" fullword ascii
    $s10 = "if (okxyW == 393-193){return true;} else {return false;}" fullword ascii
    $s11 = "return mriIT;" fullword ascii
    $s12 = "function YOPg(AjsIu) {" fullword ascii
    $s13 = "return OtJu.ExpandEnvironmentStrings(voiGN);" fullword ascii
    $s14 = "return ffcver/*ykSeTKc7CYUxIsFQoDr1ZVYep*/.position=623-623;" fullword ascii
    $s15 = "if (y >= AjsIu.length) {break;}" fullword ascii
    $s16 = "return Lmrb[tDHJyY[0]];" fullword ascii
    $s17 = "bRY = l; break; " fullword ascii
    $s18 = "function MRja(cnvXx) {" fullword ascii
    $s19 = "function UOND(zvbxL) {" fullword ascii
    $s20 = "function wxHcF(ffcver) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}