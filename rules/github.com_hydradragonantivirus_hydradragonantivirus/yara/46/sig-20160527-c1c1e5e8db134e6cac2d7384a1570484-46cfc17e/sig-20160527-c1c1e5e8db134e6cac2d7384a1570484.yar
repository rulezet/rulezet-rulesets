rule sig_20160527_c1c1e5e8db134e6cac2d7384a1570484 {
  meta:
    description = "datamaliciousorder - file 20160527_c1c1e5e8db134e6cac2d7384a1570484.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8cb87358848e89ed7f0b2d61a1e03338e20508456c05536e989a58f852ddb9a8"

  strings:
    $s1  = "function ELjLSkZ() {return WScript;}function pMYiZBPZ(){return SpnmWDFpbROl.ExpandEnvironmentStrings(dijoM())}" fullword ascii
    $s2  = "function HIZrqD(mAcEdzXiUeWRs) {var GhDBECgjxK = GLOGMwom.join(oXTTtIlzBLDbT[6]);var RwrLbTBIKRdhFqtiPaIw, ZBUiQXuHxUCQaVHDE, nN" ascii
    $s3  = "function HDvGYoppQQfHZKL(hgotVIO,XoegcWyO){return hgotVIO.charAt(XoegcWyO);}" fullword ascii
    $s4  = "function bINGDIMSxTo(){return lsrDJYPiiEn(oXTTtIlzBLDbT[12],[0,3,6],oXTTtIlzBLDbT[13]);}" fullword ascii
    $s5  = "function HIZrqD(mAcEdzXiUeWRs) {var GhDBECgjxK = GLOGMwom.join(oXTTtIlzBLDbT[6]);var RwrLbTBIKRdhFqtiPaIw, ZBUiQXuHxUCQaVHDE, nN" ascii
    $s6  = "function LisPENFCziI(BiUwOqnTANbizQ,DzNrGBnhOir) {var cwyQmgycQb=[oXTTtIlzBLDbT[15]];BiUwOqnTANbizQ[cwyQmgycQb[0]](DzNrGBnhOir,0" ascii
    $s7  = "function lsrDJYPiiEn(UmwQgPVGsII,qkOybmYqrVtaQ,NJgOLas){gXgeJQkDhUEoO=UmwQgPVGsII.split(NJgOLas);YphHOjSGWoiCBC = oXTTtIlzBLDbT[" ascii
    $s8  = "function X(IOmwsQq){return String.fromCharCode(IOmwsQq);}" fullword ascii
    $s9  = "function oBgUjMG(xNoyFbXtbtikX,CkjuTyxEBcrNdqGwNHxFrhLW,TjFYUGOxZHG){return String.fromCharCode(xNoyFbXtbtikX,CkjuTyxEBcrNdqGwNH" ascii
    $s10 = "var SpnmWDFpbROl=function(){return ELjLSkZ().CreateObject(oXTTtIlzBLDbT[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s11 = "rCode(92)+oXTTtIlzBLDbT[4],true);" fullword ascii
    $s12 = "function lsrDJYPiiEn(UmwQgPVGsII,qkOybmYqrVtaQ,NJgOLas){gXgeJQkDhUEoO=UmwQgPVGsII.split(NJgOLas);YphHOjSGWoiCBC = oXTTtIlzBLDbT[" ascii
    $s13 = "uUYyb += oBgUjMG(RwrLbTBIKRdhFqtiPaIw, ZBUiQXuHxUCQaVHDE, nNULlKvvSF);} while (bEcrcdl < mAcEdzXiUeWRs.length);return fZcjKGLGZu" ascii
    $s14 = "function LisPENFCziI(BiUwOqnTANbizQ,DzNrGBnhOir) {var cwyQmgycQb=[oXTTtIlzBLDbT[15]];BiUwOqnTANbizQ[cwyQmgycQb[0]](DzNrGBnhOir,0" ascii
    $s15 = "yH]];}return YphHOjSGWoiCBC.substring(3,YphHOjSGWoiCBC.length);}" fullword ascii
    $s16 = "function oBgUjMG(xNoyFbXtbtikX,CkjuTyxEBcrNdqGwNHxFrhLW,TjFYUGOxZHG){return String.fromCharCode(xNoyFbXtbtikX,CkjuTyxEBcrNdqGwNH" ascii
    $s17 = "function bcEsgxULbWtBsexQmq(JWmDmBZMJnmynHYEKgSCU,iKMSlJCUn){return JWmDmBZMJnmynHYEKgSCU.indexOf(iKMSlJCUn);}" fullword ascii
    $s18 = "function DqHAOJgvwFSK(){return lsrDJYPiiEn(oXTTtIlzBLDbT[10],[2,4,8,10],oXTTtIlzBLDbT[11]);}" fullword ascii
    $s19 = "function dijoM(){return lsrDJYPiiEn(oXTTtIlzBLDbT[8],[1,5,7],oXTTtIlzBLDbT[9]);}" fullword ascii
    $s20 = "function zCAMvIxtMGsejnBhxVsQ(yIGrmtOOPHe,slcQAAAaYCUgFjs){return String.fromCharCode(yIGrmtOOPHe,slcQAAAaYCUgFjs);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}