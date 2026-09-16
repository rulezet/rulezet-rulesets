rule sig_20160531_083833aa191b90db3b5f21c43d275e3b {
  meta:
    description = "datamaliciousorder - file 20160531_083833aa191b90db3b5f21c43d275e3b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dcaf314bb8470624e79ac90bf42e5599af9a2ba05a336c7d2c231501be0909d7"

  strings:
    $s1  = "var eCdspvva=function(){return WScript.CreateObject(NltSycuJIygTNK[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function TESYHr(qnkNJmsVSeQiBehHNm,lFrwbybnSLVsGgiqDORbEZ){return qnkNJmsVSeQiBehHNm.charAt(lFrwbybnSLVsGgiqDORbEZ);}" fullword ascii
    $s3  = "function WTWXFEGPbyf(){return UvjQAOPgFzEpa(NltSycuJIygTNK[11],[2,4,8,10],NltSycuJIygTNK[12]);}" fullword ascii
    $s4  = "function w(LZeTFdWCU){return String.fromCharCode(LZeTFdWCU);}" fullword ascii
    $s5  = "function oAZNIsJDfykB(XRQFbCOLSKMjWwHbg,IZTaBkJsdiHGSTfVMDDi,LtbKOuUojtXeSL){return String.fromCharCode(XRQFbCOLSKMjWwHbg,IZTaBk" ascii
    $s6  = "function YzAbr(){return UvjQAOPgFzEpa(NltSycuJIygTNK[13],[0,3,6],NltSycuJIygTNK[14]);}" fullword ascii
    $s7  = "wYYyvKq=0;oZlYwYYyvKq<JNjgANxWBZUr.length;oZlYwYYyvKq++) {EovUdCw+=GLuNhQtdvJF[JNjgANxWBZUr[oZlYwYYyvKq]];}return EovUdCw.substr" ascii
    $s8  = "LgzyrYhQahYZHmY, RCtHLSHtAUOTTCJIHYFu);else THSvMIDqAzHcSI += oAZNIsJDfykB(YLgzyrYhQahYZHmY, RCtHLSHtAUOTTCJIHYFu, mmeSBOaCx);} " ascii
    $s9  = "function UvjQAOPgFzEpa(eXOgokuWzMq,JNjgANxWBZUr,sxzPP){GLuNhQtdvJF=eXOgokuWzMq.split(sxzPP);EovUdCw = NltSycuJIygTNK[0];for(oZlY" ascii
    $s10 = "function GoNPkUnuuGrfPVKiweksDheB(GaAbROQrhImgvDzO,GjVmvZUMdHM){return GaAbROQrhImgvDzO.indexOf(GjVmvZUMdHM);}" fullword ascii
    $s11 = "function pIgBmhbBXzZ(){return UvjQAOPgFzEpa(NltSycuJIygTNK[9],[1,5,7],NltSycuJIygTNK[10]);}" fullword ascii
    $s12 = "(mlYgCT,0x1,0x0)}function dQoOLOk(dsqtypzv,vpuQrEhissmgkY,kNzMZwkykJZvV){var FvItT=dsqtypzv.createtextfile(vpuQrEhissmgkY,true);" ascii
    $s13 = "function woTmck(){return eCdspvva.ExpandEnvironmentStrings(pIgBmhbBXzZ())}" fullword ascii
    $s14 = "function UvjQAOPgFzEpa(eXOgokuWzMq,JNjgANxWBZUr,sxzPP){GLuNhQtdvJF=eXOgokuWzMq.split(sxzPP);EovUdCw = NltSycuJIygTNK[0];for(oZlY" ascii
    $s15 = "function wDOtkdHC(jlCcU,mlYgCT) {var RCHhgYCbUJr=[NltSycuJIygTNK[15]];jlCcU[RCHhgYCbUJr[0]]" fullword ascii
    $s16 = "var admiWMVKFhW=function(){return new ActiveXObject(NltSycuJIygTNK[1]);}();" fullword ascii
    $s17 = "(mlYgCT,0x1,0x0)}function dQoOLOk(dsqtypzv,vpuQrEhissmgkY,kNzMZwkykJZvV){var FvItT=dsqtypzv.createtextfile(vpuQrEhissmgkY,true);" ascii
    $s18 = "function oAZNIsJDfykB(XRQFbCOLSKMjWwHbg,IZTaBkJsdiHGSTfVMDDi,LtbKOuUojtXeSL){return String.fromCharCode(XRQFbCOLSKMjWwHbg,IZTaBk" ascii
    $s19 = "function QvGPtt(PnodteuKGDcAS) {var ZEyrrQdrTSNYOhv = xXUcDmBVM.join(NltSycuJIygTNK[7]);var YLgzyrYhQahYZHmY, RCtHLSHtAUOTTCJIHY" ascii
    $s20 = "function SRcaLxYrnDtgTGurEltMB(dHVnjFLMhPqrOdfW,XtINLbAjVkDsAbSnXIatdBbE){return String.fromCharCode(dHVnjFLMhPqrOdfW,XtINLbAjVk" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}