rule sig_20160531_3b57052eb7311000013ebb2e7310e6df {
  meta:
    description = "datamaliciousorder - file 20160531_3b57052eb7311000013ebb2e7310e6df.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9cc2eeda74eb6bc4e2e3afc2c3fde350039abbc7198694af3351b573f372bbf2"

  strings:
    $s1  = "var rrBTDB=function(){return WScript.CreateObject(kbcjCRvWceEENZglrxuu[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function YtrMXywUcZZBtlYKwsNM(HDBmHZXoFHOGl,TEBDqlVhzpVIplzIIhB){return HDBmHZXoFHOGl.charAt(TEBDqlVhzpVIplzIIhB);}" fullword ascii
    $s3  = "var xxQoJEPDEp=function(){return new ActiveXObject(kbcjCRvWceEENZglrxuu[1]);}();" fullword ascii
    $s4  = "function YOxRmLXnz(){return vnrvqdT(kbcjCRvWceEENZglrxuu[9],[1,5,7],kbcjCRvWceEENZglrxuu[10]);}" fullword ascii
    $s5  = "function QDxXBduHPTYgpLrOOPcRM(mFnRYsbIPexqKMq,hjUBBHfxjtomUZOaBetpjLjW){return String.fromCharCode(mFnRYsbIPexqKMq,hjUBBHfxjtom" ascii
    $s6  = "function vnrvqdT(uTftKyU,sgGHI,Tyior){NwngpGCpXsvcy=uTftKyU.split(Tyior);ZWjJJLcc = kbcjCRvWceEENZglrxuu[0];for(bZSdbbYtEZhyVa=0" ascii
    $s7  = ";bZSdbbYtEZhyVa<sgGHI.length;bZSdbbYtEZhyVa++) {ZWjJJLcc+=NwngpGCpXsvcy[sgGHI[bZSdbbYtEZhyVa]];}return ZWjJJLcc.substring(3,ZWjJ" ascii
    $s8  = "function QDxXBduHPTYgpLrOOPcRM(mFnRYsbIPexqKMq,hjUBBHfxjtomUZOaBetpjLjW){return String.fromCharCode(mFnRYsbIPexqKMq,hjUBBHfxjtom" ascii
    $s9  = "QPwUv += WI(bzmdvgOtUy);else if (xbiFFdEAKhGte == 64) lrxVgCDTaVihvQPwUv += QDxXBduHPTYgpLrOOPcRM(bzmdvgOtUy, eLJkWxQ);else lrxV" ascii
    $s10 = "function yORKOwGwxUS(JHfhVuYKinsmo) {var MYBUcGqPUmHnDuX = JQvEDLdugpPOLunwBc.join(kbcjCRvWceEENZglrxuu[7]);var bzmdvgOtUy, eLJk" ascii
    $s11 = "push(\"D\");JQvEDLdugpPOLunwBc.push(\"3\");JQvEDLdugpPOLunwBc.push(\"E\");JQvEDLdugpPOLunwBc.push(\"F\");JQvEDLdugpPOLunwBc.push" ascii
    $s12 = "(zruZkkQtWezHE,0x1,0x0)}function VBmtJALbTzk(HVkhQQ,mcZQz,cIpJIrxQKMEr){var uXhtMEQmrw=HVkhQQ.createtextfile(mcZQz,true);uXhtMEQ" ascii
    $s13 = "mo.length);return lrxVgCDTaVihvQPwUv;}" fullword ascii
    $s14 = "function vnrvqdT(uTftKyU,sgGHI,Tyior){NwngpGCpXsvcy=uTftKyU.split(Tyior);ZWjJJLcc = kbcjCRvWceEENZglrxuu[0];for(bZSdbbYtEZhyVa=0" ascii
    $s15 = "function WI(mCWgPhbquClgxnmoBU){return String.fromCharCode(mCWgPhbquClgxnmoBU);}" fullword ascii
    $s16 = "function cnaEAywQv(){return vnrvqdT(kbcjCRvWceEENZglrxuu[13],[0,3,6],kbcjCRvWceEENZglrxuu[14]);}" fullword ascii
    $s17 = "function PQnPrIeCLIaym(){return rrBTDB.ExpandEnvironmentStrings(YOxRmLXnz())}" fullword ascii
    $s18 = "function itvwZSHY(){return vnrvqdT(kbcjCRvWceEENZglrxuu[11],[2,4,8,10],kbcjCRvWceEENZglrxuu[12]);}" fullword ascii
    $s19 = "function HbGaxpk(ikOClJHEhscOl,lAVFvgwY){return ikOClJHEhscOl.indexOf(lAVFvgwY);}" fullword ascii
    $s20 = "(zruZkkQtWezHE,0x1,0x0)}function VBmtJALbTzk(HVkhQQ,mcZQz,cIpJIrxQKMEr){var uXhtMEQmrw=HVkhQQ.createtextfile(mcZQz,true);uXhtMEQ" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}