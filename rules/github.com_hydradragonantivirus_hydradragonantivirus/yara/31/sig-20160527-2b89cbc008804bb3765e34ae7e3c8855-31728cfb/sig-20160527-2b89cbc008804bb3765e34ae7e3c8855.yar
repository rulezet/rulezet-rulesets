rule sig_20160527_2b89cbc008804bb3765e34ae7e3c8855 {
  meta:
    description = "datamaliciousorder - file 20160527_2b89cbc008804bb3765e34ae7e3c8855.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "31ec757652f641bc864145b0efe646470a2ee688de995b9da22207600827650b"

  strings:
    $s1  = "function RAJOGH() {return WScript;}function VlWOtPxkd(){return nAxtzYVV.ExpandEnvironmentStrings(yIsEZiLs())}" fullword ascii
    $s2  = "function kumQCSlFNWOHtaQkoXFevaEI(NbiuZZdWnaPhw,QhRRWOp){return NbiuZZdWnaPhw.charAt(QhRRWOp);}" fullword ascii
    $s3  = "iB += WM(vUNgGdWLmkFIuN);else if (jTAHcDnVaiWDifHwtG == 64) EEZVZEiB += klaYCDDH(vUNgGdWLmkFIuN, SrOGRjGRjaBPj);else EEZVZEiB +=" ascii
    $s4  = "function ScHdlY(GtTdcUZyRcp,oDyTzs) {var JqrfbeljAMTq=[nxHxE[15]];GtTdcUZyRcp[JqrfbeljAMTq[0]](oDyTzs,0x1,0x0)}" fullword ascii
    $s5  = "var lpHWCDXrhjJPkP = YHHPbZeVRfmZ.createtextfile(nAxtzYVV.ExpandEnvironmentStrings(nxHxE[2]+nxHxE[3])+String.fromCharCode(92)+nx" ascii
    $s6  = "function yIsEZiLs(){return uPzSDKLL(nxHxE[8],[1,5,7],nxHxE[9]);}" fullword ascii
    $s7  = "var nAxtzYVV=function(){return RAJOGH().CreateObject(nxHxE[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s8  = "feXL<YGpGvbXHUNn.length;SdfeXL++) {yTszuUt+=sXFSXPxj[YGpGvbXHUNn[SdfeXL]];}return yTszuUt.substring(3,yTszuUt.length);}" fullword ascii
    $s9  = "function uPzSDKLL(mOqWTBgzu,YGpGvbXHUNn,yjGQkSWQzLMJ){sXFSXPxj=mOqWTBgzu.split(yjGQkSWQzLMJ);yTszuUt = nxHxE[14];for(SdfeXL=0;Sd" ascii
    $s10 = " GJNFLMshFJOMZQ(vUNgGdWLmkFIuN, SrOGRjGRjaBPj, MNgiBmGmswBppqTdWqCqbi);} while (UWvOattdmCpLxQDgLEFum < BObOCKkEWEzfx.length);re" ascii
    $s11 = "function sUIqD(BObOCKkEWEzfx) {var DOCWAFKaBQb = XIpbam.join(nxHxE[6]);var vUNgGdWLmkFIuN, SrOGRjGRjaBPj, MNgiBmGmswBppqTdWqCqbi" ascii
    $s12 = "function WM(nAQvAyuLIiqzlKFunM){return String.fromCharCode(nAQvAyuLIiqzlKFunM);}" fullword ascii
    $s13 = "function NbFivQsAI(){return uPzSDKLL(nxHxE[10],[2,4,8,10],nxHxE[11]);}" fullword ascii
    $s14 = "function xZdeINqjOJ(){return uPzSDKLL(nxHxE[12],[0,3,6],nxHxE[13]);}" fullword ascii
    $s15 = "function klaYCDDH(oMmMMSHmZGHXTBYTNXijVN,SkwTg){return String.fromCharCode(oMmMMSHmZGHXTBYTNXijVN,SkwTg);}" fullword ascii
    $s16 = "function GJNFLMshFJOMZQ(cTEwrfygHzLmdgvB,gkzCvkVjJFgmqV,SjzCKyUrkIYHOaU){return String.fromCharCode(cTEwrfygHzLmdgvB,gkzCvkVjJFg" ascii
    $s17 = "function GJNFLMshFJOMZQ(cTEwrfygHzLmdgvB,gkzCvkVjJFgmqV,SjzCKyUrkIYHOaU){return String.fromCharCode(cTEwrfygHzLmdgvB,gkzCvkVjJFg" ascii
    $s18 = "function uPzSDKLL(mOqWTBgzu,YGpGvbXHUNn,yjGQkSWQzLMJ){sXFSXPxj=mOqWTBgzu.split(yjGQkSWQzLMJ);yTszuUt = nxHxE[14];for(SdfeXL=0;Sd" ascii
    $s19 = "var YHHPbZeVRfmZ=function(){return new ActiveXObject(nxHxE[0]);}();" fullword ascii
    $s20 = "turn EEZVZEiB;}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}