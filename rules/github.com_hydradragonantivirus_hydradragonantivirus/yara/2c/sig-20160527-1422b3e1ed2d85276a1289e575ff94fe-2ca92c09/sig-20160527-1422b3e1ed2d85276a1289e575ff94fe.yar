rule sig_20160527_1422b3e1ed2d85276a1289e575ff94fe {
  meta:
    description = "datamaliciousorder - file 20160527_1422b3e1ed2d85276a1289e575ff94fe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86d22c2a5edf889ca5bff9d203c34a99427a1661849b00a8cf9971131751c982"

  strings:
    $s1  = "function NzdHuRmdy() {return WScript;}function bhaIwpjsfbe(){return EewdljCkaCjNvk.ExpandEnvironmentStrings(TdnOJ())}" fullword ascii
    $s2  = "function AmLgCzPOTjVMZNRiByIkmb(ggMRGsPbrcSgUHdpzGxi,RdAlEgX){return ggMRGsPbrcSgUHdpzGxi.charAt(RdAlEgX);}" fullword ascii
    $s3  = "function suzMRMotnPqmOD(){return kcnzgErvBnPpYW(vWkeVcNaJTeYH[12],[0,3,6],vWkeVcNaJTeYH[13]);}" fullword ascii
    $s4  = "NYuMTNnXlVhVPO += vF(OSgjlaIytfaIvPcFHlvoL);else if (fXJHxhnlEmSaCFFkreluDSZM == 64) pVwNIyyBBDNYuMTNnXlVhVPO += YuCla(OSgjlaIyt" ascii
    $s5  = "function vF(VqpxEStwkMRsCyrPtmjoojSD){return String.fromCharCode(VqpxEStwkMRsCyrPtmjoojSD);}" fullword ascii
    $s6  = "function kcnzgErvBnPpYW(vFQsyvNVQn,NhqnBka,YLBuJJMisgmRX){tBexOXAAknNemv=vFQsyvNVQn.split(YLBuJJMisgmRX);DKpWNEG = vWkeVcNaJTeYH" ascii
    $s7  = "function kcnzgErvBnPpYW(vFQsyvNVQn,NhqnBka,YLBuJJMisgmRX){tBexOXAAknNemv=vFQsyvNVQn.split(YLBuJJMisgmRX);DKpWNEG = vWkeVcNaJTeYH" ascii
    $s8  = "function TdnOJ(){return kcnzgErvBnPpYW(vWkeVcNaJTeYH[8],[1,5,7],vWkeVcNaJTeYH[9]);}" fullword ascii
    $s9  = "var PXllGAuLB = IJrJZQSFIEK.createtextfile(EewdljCkaCjNvk.ExpandEnvironmentStrings(vWkeVcNaJTeYH[2]+vWkeVcNaJTeYH[3])+String.fro" ascii
    $s10 = "function YuCla(VPsuGCSO,AGUlFDdpTE){return String.fromCharCode(VPsuGCSO,AGUlFDdpTE);}" fullword ascii
    $s11 = "function nSsMVJGoPtJDJM(JuEHVfwOKWBvn) {var TkFlwDnQnvrHxqAMmJteaYeL = NecvQvTSImWNOEHtRvRNxUcr.join(vWkeVcNaJTeYH[6]);var OSgjl" ascii
    $s12 = "function nroWfzObupzrO(nSKyV,mWqRm) {var CPNuaHsre=[vWkeVcNaJTeYH[15]];nSKyV[CPNuaHsre[0]](mWqRm,0x1,0x0)}" fullword ascii
    $s13 = "var EewdljCkaCjNvk=function(){return NzdHuRmdy().CreateObject(vWkeVcNaJTeYH[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s14 = "function gsRomNubroz(){return kcnzgErvBnPpYW(vWkeVcNaJTeYH[10],[2,4,8,10],vWkeVcNaJTeYH[11]);}" fullword ascii
    $s15 = "var IJrJZQSFIEK=function(){return new ActiveXObject(vWkeVcNaJTeYH[0]);}();" fullword ascii
    $s16 = "mCharCode(92)+vWkeVcNaJTeYH[4],true);" fullword ascii
    $s17 = "FhrGGNFty, GQWlD);} while (DfkwXJHphduKjTANq < JuEHVfwOKWBvn.length);return pVwNIyyBBDNYuMTNnXlVhVPO;}" fullword ascii
    $s18 = "push(\"v\");NecvQvTSImWNOEHtRvRNxUcr.push(\"w\");NecvQvTSImWNOEHtRvRNxUcr.push(\"x\");NecvQvTSImWNOEHtRvRNxUcr.push(\"y\");NecvQ" ascii
    $s19 = "function ZjuYftDf(LOeiZssDgnIQzmkaY,MvsdVVSmQMjcMWBZoq){return LOeiZssDgnIQzmkaY.indexOf(MvsdVVSmQMjcMWBZoq);}" fullword ascii
    $s20 = "[14];for(rsielXVplxar=0;rsielXVplxar<NhqnBka.length;rsielXVplxar++) {DKpWNEG+=tBexOXAAknNemv[NhqnBka[rsielXVplxar]];}return DKpW" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}