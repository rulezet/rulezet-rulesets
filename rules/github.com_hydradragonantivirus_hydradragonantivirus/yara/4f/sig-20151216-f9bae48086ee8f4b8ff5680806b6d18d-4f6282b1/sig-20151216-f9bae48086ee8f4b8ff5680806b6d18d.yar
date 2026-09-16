rule sig_20151216_f9bae48086ee8f4b8ff5680806b6d18d {
  meta:
    description = "datamaliciousorder - file 20151216_f9bae48086ee8f4b8ff5680806b6d18d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "06dc214c719ee11f68b09114313b13c31783133e9d463c1f486ab68536864e99"

  strings:
    $s1  = "function WbyKQuyNVtWSvoUOL(yWXpS){RXnuOtOKllV= '';mIAUYVzihVI=Math.round((Math.pow(Math.sin(678), 2) + Math.pow(Math.cos(678), 2" ascii
    $s2  = "th.pow(Math.cos(344), 2) - 1)); while(true) { if(FyLHwUyWU[mIAUYVzihVI] > yWXpS[mIAUYVzihVI].length-(386+400)/786) { break; } if" ascii
    $s3  = ") - 1));while(true){if (mIAUYVzihVI >= (4640+544)/864){break;}FyLHwUyWU[mIAUYVzihVI]=Math.round((Math.pow(Math.sin(344), 2) + Ma" ascii
    $s4  = "ow(Math.cos(469), 2) - 1)));} FyLHwUyWU[mIAUYVzihVI]++;}mIAUYVzihVI++;} return RXnuOtOKllV}" fullword ascii
    $s5  = "function WbyKQuyNVtWSvoUOL(yWXpS){RXnuOtOKllV= '';mIAUYVzihVI=Math.round((Math.pow(Math.sin(678), 2) + Math.pow(Math.cos(678), 2" ascii
    $s6  = "function aXdHUxb(DyhtHCRvxBkMFTAfeVUbfjDAODjgDSKdrEFv) {return !pVCTCRrKBhm(kzNPDuQAbfrdtCY(DyhtHCRvxBkMFTAfeVUbfjDAODjgDSKdrEFv" ascii
    $s7  = "var I = new Array();I[0]=[];I[0][0]='d';I[0][1]='a';I[0][2]='d';I[0][3]='a';I[0][4]='46';I[0][5]='3d';I[0][6]='42';I[0][7]='14';" ascii
    $s8  = "function ZiCBG(FMZUrBKXcGq,apAzrynzDcbtw,LwKRTNgc){pDxH=sOidmOuKKSOpaMraq(FMZUrBKXcGq,apAzrynzDcbtw);lvEgq=pDxH.toString(LwKRTNg" ascii
    $s9  = "function ZiCBG(FMZUrBKXcGq,apAzrynzDcbtw,LwKRTNgc){pDxH=sOidmOuKKSOpaMraq(FMZUrBKXcGq,apAzrynzDcbtw);lvEgq=pDxH.toString(LwKRTNg" ascii
    $s10 = "function pGOsruqQuIfMCWddxixsBjkxXqqGmRflugsbtANcFgLOAtEAEkeqKz(TmAdBacWOrETK,ThEMQuxsArbgBr){ return MuNVTeE[kjjnbKIx[ZiCBG(TmA" ascii
    $s11 = "function sOidmOuKKSOpaMraq(iKKJhHmYtS,EFrlottTxR) {return parseInt(iKKJhHmYtS,EFrlottTxR);}" fullword ascii
    $s12 = "function kzNPDuQAbfrdtCY(FmDOTYZORxRbCtkoshl) {return parseFloat(FmDOTYZORxRbCtkoshl);}" fullword ascii
    $s13 = "c);return lvEgq;}" fullword ascii
    $s14 = "function ahhBSWDEsbwfSgR(ugeFaThVWWMuGRxqC,ENbvBKBkSxNctGqExiYlrBErsDFVpHSWzv,EONORSppAfsJTkUwDgjVbgCfntWccmWSZIu){eval(ugeFaThV" ascii
    $s15 = "function ahhBSWDEsbwfSgR(ugeFaThVWWMuGRxqC,ENbvBKBkSxNctGqExiYlrBErsDFVpHSWzv,EONORSppAfsJTkUwDgjVbgCfntWccmWSZIu){eval(ugeFaThV" ascii
    $s16 = "function mjkjRdigkONW(gLOAtUkqzhFZQ) {return isFinite(gLOAtUkqzhFZQ);}" fullword ascii
    $s17 = "var I = new Array();I[0]=[];I[0][0]='d';I[0][1]='a';I[0][2]='d';I[0][3]='a';I[0][4]='46';I[0][5]='3d';I[0][6]='42';I[0][7]='14';" ascii
    $s18 = "function Y(MkQQWpDSTpZGqS,DvQeTEwuFrlFX,YMrsYQlhJQd) {MkQQWpDSTpZGqS[DvQeTEwuFrlFX]=YMrsYQlhJQd;}" fullword ascii
    $s19 = "function pVCTCRrKBhm(FqFhJzmfajFhKL) {return isNaN(FqFhJzmfajFhKL);}" fullword ascii
    $s20 = "function m(rmXBXUcEElSe,xBtLVUBgzUVrMM){rmXBXUcEElSe.push(xBtLVUBgzUVrMM);}" fullword ascii

  condition:
    uint16(0) == 0x6a6b and
    8 of them
}