rule sig_20160310_3fd477c22ef5cc05098efff7722378a0 {
  meta:
    description = "datamaliciousorder - file 20160310_3fd477c22ef5cc05098efff7722378a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fbcd5b65b5022255b52fa3c704032ea96060cff96637c7dbf7ae4f54472462ff"

  strings:
    $s1  = "return NaZvWQZ[0] + NaZvWQZ[2] + NaZvWQZ[4] + \".F\" + NaZvWQZ[7] + NaZvWQZ[9] + NaZvWQZ[12] + NaZvWQZ[14];" fullword ascii
    $s2  = "var Xo = true  , aqzm = ujV[7] + ujV[9] + ujV[11];" fullword ascii
    $s3  = "XZabP.open(CttpS,atlsk,false);" fullword ascii
    $s4  = "var NaZvWQZ = \"Sc RSAbxxK r yijpkKpFI ipting vEuHOvN EVF ile QdeZcgQladTUcW System IF vElLR Obj ELHZLb ect BBtOVlB\".split(\" " ascii
    $s5  = "if(W>=q.length) {break;}" fullword ascii
    $s6  = "if (BEaxk == 609-409){return true;} else {return false;}" fullword ascii
    $s7  = "function YVBl(GdRzf) {" fullword ascii
    $s8  = "function nysc(BdPmN) {" fullword ascii
    $s9  = "function abtOXyNgB(ZNOFwTCyyhK) {" fullword ascii
    $s10 = "function SWyYmaQSI(tDXAx,XAZJb,LVHwa,rVWp) {" fullword ascii
    $s11 = "function AAYu(BpMAD,jSYBS) {" fullword ascii
    $s12 = "function AxrqIQfC(fQWau,iaQOqi) {" fullword ascii
    $s13 = "IRq = W; break; " fullword ascii
    $s14 = "return iZC.size;" fullword ascii
    $s15 = "return VOtfH;" fullword ascii
    $s16 = "return aQowvS.position=720-720;" fullword ascii
    $s17 = "function hFtL(FnPav) {" fullword ascii
    $s18 = "function yiaJzFg(jpeG,WOvYx) {" fullword ascii
    $s19 = "function mxRklpTx(iZC) {" fullword ascii
    $s20 = "function gvYnmYUE() {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}