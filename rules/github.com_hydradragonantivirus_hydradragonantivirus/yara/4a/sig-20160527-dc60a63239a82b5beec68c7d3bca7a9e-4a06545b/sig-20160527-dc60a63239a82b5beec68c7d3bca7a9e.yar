rule sig_20160527_dc60a63239a82b5beec68c7d3bca7a9e {
  meta:
    description = "datamaliciousorder - file 20160527_dc60a63239a82b5beec68c7d3bca7a9e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cbc30c4afd75244df304410f0089089d0fce0bd64ad256befd3680b0bcbc3e31"

  strings:
    $s1  = "function KMjYaBEypJ() {return WScript;}function sWEbwCKCkdbPQ(){return SFzeCDtFbPmT.ExpandEnvironmentStrings(WBZKMmoLxWwn())}" fullword ascii
    $s2  = "function gBVPutDoAThcmcOxbNACC(kIMyzdCHvMf,UkzpafGQwHUJyaNins){return kIMyzdCHvMf.charAt(UkzpafGQwHUJyaNins);}" fullword ascii
    $s3  = "+String.fromCharCode(92)+xbbFBRfDPPQFhbvFyo[4],true);" fullword ascii
    $s4  = "function QfTOfFWCO(){return YpKFuJawR(xbbFBRfDPPQFhbvFyo[12],[0,3,6],xbbFBRfDPPQFhbvFyo[13]);}" fullword ascii
    $s5  = "var kHdKiPamtLAsrw = EbZUjgPeq.createtextfile(SFzeCDtFbPmT.ExpandEnvironmentStrings(xbbFBRfDPPQFhbvFyo[2]+xbbFBRfDPPQFhbvFyo[3])" ascii
    $s6  = "= 64) blnzLzYetkgrU += rd(BYljzUPzUo);else if (djCOPPiVjauvnGzWkAhFs == 64) blnzLzYetkgrU += FhuWtkcZBbmMWOelkfSC(BYljzUPzUo, gC" ascii
    $s7  = "jToLhxYtopC=0;YYjToLhxYtopC<xqYJm.length;YYjToLhxYtopC++) {GbhbryOyBGOExO+=mEiSNJUp[xqYJm[YYjToLhxYtopC]];}return GbhbryOyBGOExO" ascii
    $s8  = "function wGQwvL(fgGNXHCCNFZ,AfsFPgWVmgUAUvOxbDhkqk,LBLYzcmGrvCVQgPzzuonGwfr){return String.fromCharCode(fgGNXHCCNFZ,AfsFPgWVmgUA" ascii
    $s9  = "function IKZqBHLZwKD(jzmOHCqqkTdUA) {var RtkRr = kJIxEv.join(xbbFBRfDPPQFhbvFyo[6]);var BYljzUPzUo, gCvND, cIhHoMOBT, JSplc, vHS" ascii
    $s10 = "var EbZUjgPeq=function(){return new ActiveXObject(xbbFBRfDPPQFhbvFyo[0]);}();" fullword ascii
    $s11 = "function dThVQaVZROsvhbTIytTJC(udXKKkpXtQHmlQMkfOf,kBAicOddpqIhgEcWzAJgX){return udXKKkpXtQHmlQMkfOf.indexOf(kBAicOddpqIhgEcWzAJ" ascii
    $s12 = "var SFzeCDtFbPmT=function(){return KMjYaBEypJ().CreateObject(xbbFBRfDPPQFhbvFyo[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s13 = "function dThVQaVZROsvhbTIytTJC(udXKKkpXtQHmlQMkfOf,kBAicOddpqIhgEcWzAJgX){return udXKKkpXtQHmlQMkfOf.indexOf(kBAicOddpqIhgEcWzAJ" ascii
    $s14 = "function mjEhdHZ(hNtppenQPGnN,ASdoqnvOzxPS) {var bkpyJTwPa=[xbbFBRfDPPQFhbvFyo[15]];hNtppenQPGnN[bkpyJTwPa[0]](ASdoqnvOzxPS,0x1," ascii
    $s15 = "vND);else blnzLzYetkgrU += wGQwvL(BYljzUPzUo, gCvND, cIhHoMOBT);} while (mJHpYcQteDfSJCynJQ < jzmOHCqqkTdUA.length);return blnzL" ascii
    $s16 = "function rd(BVBfUihWG){return String.fromCharCode(BVBfUihWG);}" fullword ascii
    $s17 = "function mjEhdHZ(hNtppenQPGnN,ASdoqnvOzxPS) {var bkpyJTwPa=[xbbFBRfDPPQFhbvFyo[15]];hNtppenQPGnN[bkpyJTwPa[0]](ASdoqnvOzxPS,0x1," ascii
    $s18 = "function WBZKMmoLxWwn(){return YpKFuJawR(xbbFBRfDPPQFhbvFyo[8],[1,5,7],xbbFBRfDPPQFhbvFyo[9]);}" fullword ascii
    $s19 = "function yBJKrYBVGtwLN(){return YpKFuJawR(xbbFBRfDPPQFhbvFyo[10],[2,4,8,10],xbbFBRfDPPQFhbvFyo[11]);}" fullword ascii
    $s20 = "function IKZqBHLZwKD(jzmOHCqqkTdUA) {var RtkRr = kJIxEv.join(xbbFBRfDPPQFhbvFyo[6]);var BYljzUPzUo, gCvND, cIhHoMOBT, JSplc, vHS" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}