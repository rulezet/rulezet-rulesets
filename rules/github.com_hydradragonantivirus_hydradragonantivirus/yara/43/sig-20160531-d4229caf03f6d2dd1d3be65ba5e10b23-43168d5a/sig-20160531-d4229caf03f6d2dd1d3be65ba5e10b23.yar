rule sig_20160531_d4229caf03f6d2dd1d3be65ba5e10b23 {
  meta:
    description = "datamaliciousorder - file 20160531_d4229caf03f6d2dd1d3be65ba5e10b23.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "020ded42ad759df232dd4ca07cba4d24a3fd57360ff8b168c3b3b1b1ce76f9b4"

  strings:
    $s1  = "var gXCZgstTOcWy=function(){return WScript.CreateObject(emuPjJmoo[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function KyqrCddBtDTziPfvoVaZ(blmbbz,ANsPYNpD){return String.fromCharCode(blmbbz,ANsPYNpD);}" fullword ascii
    $s3  = "function VhvJAnAKif(SvSMNDZuOIYXCDyhqpLPScm,OOkntmjhTyauJtj){return SvSMNDZuOIYXCDyhqpLPScm.charAt(OOkntmjhTyauJtj);}" fullword ascii
    $s4  = "function pCOKeYd(KdVqDYEUpgcjB) {var DzXYKYLLdkjYjeuPMWpN = lbauEdP.join(emuPjJmoo[7]);var ZgbJSttcnmcyO, yVatCuipPNTtJWrPZao, F" ascii
    $s5  = "function InQrexfj(){return AvgefhEXdz(emuPjJmoo[11],[2,4,8,10],emuPjJmoo[12]);}" fullword ascii
    $s6  = "function CR(nfmcROekopGDAtlReeRueG){return String.fromCharCode(nfmcROekopGDAtlReeRueG);}" fullword ascii
    $s7  = "function AvgefhEXdz(shwGQWKvGvN,ilwBPdMe,uueqOou){fyPJALsx=shwGQWKvGvN.split(uueqOou);ocGLLfw = emuPjJmoo[0];for(hRyuos=0;hRyuos" ascii
    $s8  = "JSttcnmcyO);else if (bFtUZLwHafSrzGkwzw == 64) TIDXPoBKuUXfqqF += KyqrCddBtDTziPfvoVaZ(ZgbJSttcnmcyO, yVatCuipPNTtJWrPZao);else " ascii
    $s9  = "function SURzCNdcl(){return AvgefhEXdz(emuPjJmoo[13],[0,3,6],emuPjJmoo[14]);}" fullword ascii
    $s10 = "function knnwQZLRv(){return gXCZgstTOcWy.ExpandEnvironmentStrings(xZygFtyFTe())}" fullword ascii
    $s11 = "var YTElrxBNzg=function(){return new ActiveXObject(emuPjJmoo[1]);}();" fullword ascii
    $s12 = "function PtzmGxWXZvkq(UQNCbDJvgno,NGromt) {var toVlUqdB=[emuPjJmoo[15]];UQNCbDJvgno[toVlUqdB[0]]" fullword ascii
    $s13 = "(NGromt,0x1,0x0)}function jMGBSmcFDEi(hWjjusHubyH,BVybKW,JLarlHFbaiNAo){var bMGrdIJzaaunLw=hWjjusHubyH.createtextfile(BVybKW,tru" ascii
    $s14 = "TIDXPoBKuUXfqqF += NaGPvsw(ZgbJSttcnmcyO, yVatCuipPNTtJWrPZao, FrteSZMsaZkUKTyyZD);} while (hQkdgCF < KdVqDYEUpgcjB.length);retu" ascii
    $s15 = "(NGromt,0x1,0x0)}function jMGBSmcFDEi(hWjjusHubyH,BVybKW,JLarlHFbaiNAo){var bMGrdIJzaaunLw=hWjjusHubyH.createtextfile(BVybKW,tru" ascii
    $s16 = "<ilwBPdMe.length;hRyuos++) {ocGLLfw+=fyPJALsx[ilwBPdMe[hRyuos]];}return ocGLLfw.substring(3,ocGLLfw.length);}" fullword ascii
    $s17 = "function NaGPvsw(zvPieYum,pgrRBg,kpCSQLSFJuKAhEmfotjSn){return String.fromCharCode(zvPieYum,pgrRBg,kpCSQLSFJuKAhEmfotjSn);}" fullword ascii
    $s18 = "function AvgefhEXdz(shwGQWKvGvN,ilwBPdMe,uueqOou){fyPJALsx=shwGQWKvGvN.split(uueqOou);ocGLLfw = emuPjJmoo[0];for(hRyuos=0;hRyuos" ascii
    $s19 = "function xZygFtyFTe(){return AvgefhEXdz(emuPjJmoo[9],[1,5,7],emuPjJmoo[10]);}" fullword ascii
    $s20 = "function pCOKeYd(KdVqDYEUpgcjB) {var DzXYKYLLdkjYjeuPMWpN = lbauEdP.join(emuPjJmoo[7]);var ZgbJSttcnmcyO, yVatCuipPNTtJWrPZao, F" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}