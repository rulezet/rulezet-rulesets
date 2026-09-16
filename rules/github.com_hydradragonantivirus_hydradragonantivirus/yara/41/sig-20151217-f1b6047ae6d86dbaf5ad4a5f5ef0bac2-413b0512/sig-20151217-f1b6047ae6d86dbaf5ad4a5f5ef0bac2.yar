rule sig_20151217_f1b6047ae6d86dbaf5ad4a5f5ef0bac2 {
  meta:
    description = "datamaliciousorder - file 20151217_f1b6047ae6d86dbaf5ad4a5f5ef0bac2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5bc18eb90a939e8af0c89b291c1d8a9632794f6391c07f9ed1918545b1875a48"

  strings:
    $s1  = "th.pow(Math.cos(946), 2) - 1)); while(true) { if(wNQVqIPQn[ZYVaJBGysMs] > FzrFN[ZYVaJBGysMs].length-(112+501)/613) { break; } if" ascii
    $s2  = "function BBOiffaAGFpFdUwPB(FzrFN){zXwVqnYtWVW= '';ZYVaJBGysMs=Math.round((Math.pow(Math.sin(930), 2) + Math.pow(Math.cos(930), 2" ascii
    $s3  = ") - 1));while(true){if (ZYVaJBGysMs >= (3972+174)/691){break;}wNQVqIPQn[ZYVaJBGysMs]=Math.round((Math.pow(Math.sin(946), 2) + Ma" ascii
    $s4  = "(Math.cos(934), 2) - 1)));} wNQVqIPQn[ZYVaJBGysMs]++;}ZYVaJBGysMs++;} return zXwVqnYtWVW}" fullword ascii
    $s5  = "function BBOiffaAGFpFdUwPB(FzrFN){zXwVqnYtWVW= '';ZYVaJBGysMs=Math.round((Math.pow(Math.sin(930), 2) + Math.pow(Math.cos(930), 2" ascii
    $s6  = "function ncbmv(CVJFzgllyxp,tQySoeKNmIUnv,jiBInqIm){hgUr=oincwZBDdpCXWOzHL(CVJFzgllyxp,tQySoeKNmIUnv);JygKU=hgUr.toString(jiBInqI" ascii
    $s7  = "function JGAxJGN(YhhmIXPWSzDaCuBgiMmLnwsuHDgSThMxIgDO) {return !VdFyBhbELub(RjGYuCRRteJVBKh(YhhmIXPWSzDaCuBgiMmLnwsuHDgSThMxIgDO" ascii
    $s8  = "function ncbmv(CVJFzgllyxp,tQySoeKNmIUnv,jiBInqIm){hgUr=oincwZBDdpCXWOzHL(CVJFzgllyxp,tQySoeKNmIUnv);JygKU=hgUr.toString(jiBInqI" ascii
    $s9  = "var H = new Array();H[0]=[];H[0][0]='d';H[0][1]='a';H[0][2]='d';H[0][3]='a';H[0][4]='46';H[0][5]='3d';H[0][6]='42';H[0][7]='14';" ascii
    $s10 = "function RjGYuCRRteJVBKh(IMSGEDPUQaeSBcgoZKI) {return parseFloat(IMSGEDPUQaeSBcgoZKI);}" fullword ascii
    $s11 = "function PLWIXLrahUqImzOySrhSYxZRuDlMnDLerPcuHdUPeQnxsMiQflPuwr(KKzquXCVQQRcy,vxtDMImdVNKkPb){ return lZgglyY[mBNWEEVp[ncbmv(KKz" ascii
    $s12 = "function gsdGXuyNQTyg(VXRYOsBYgSZGE) {return isFinite(VXRYOsBYgSZGE);}" fullword ascii
    $s13 = "function N(zMcRrWPATvdEbO,NOuRZjXuloRlm,yGKkNhFucMn) {zMcRrWPATvdEbO[NOuRZjXuloRlm]=yGKkNhFucMn;}" fullword ascii
    $s14 = "function VdFyBhbELub(hTVlGtAjMmzrPZ) {return isNaN(hTVlGtAjMmzrPZ);}" fullword ascii
    $s15 = ",'s','l','k','V','W','\"','+','9','#','X','s','h','g','a','(','Y','6','#','q','Z','$','c','q','V','4','[','[','-','r','M',String" ascii
    $s16 = "function oincwZBDdpCXWOzHL(iQTIraWuQF,ssVLwXCxiK) {return parseInt(iQTIraWuQF,ssVLwXCxiK);}" fullword ascii
    $s17 = "function GujNPGMMKnBrYFT(eixKYqfAsKuYefGhQ,JPgaQBDHtLGtqQyFJFQdcSqdxTrQTGozlO,WpsvGkJrpSVIvEvojbJDMLSRFSrgPRBcVjS){eval(eixKYqfA" ascii
    $s18 = "function GujNPGMMKnBrYFT(eixKYqfAsKuYefGhQ,JPgaQBDHtLGtqQyFJFQdcSqdxTrQTGozlO,WpsvGkJrpSVIvEvojbJDMLSRFSrgPRBcVjS){eval(eixKYqfA" ascii
    $s19 = "function PLWIXLrahUqImzOySrhSYxZRuDlMnDLerPcuHdUPeQnxsMiQflPuwr(KKzquXCVQQRcy,vxtDMImdVNKkPb){ return lZgglyY[mBNWEEVp[ncbmv(KKz" ascii
    $s20 = "function c(DLiNjMHYqAyu,BDjkKqObJyGMgr){DLiNjMHYqAyu.push(BDjkKqObJyGMgr);}" fullword ascii

  condition:
    uint16(0) == 0x426d and
    8 of them
}