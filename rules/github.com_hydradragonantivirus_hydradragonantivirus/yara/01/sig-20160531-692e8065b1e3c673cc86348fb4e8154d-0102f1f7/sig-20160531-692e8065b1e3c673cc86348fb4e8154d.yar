rule sig_20160531_692e8065b1e3c673cc86348fb4e8154d {
  meta:
    description = "datamaliciousorder - file 20160531_692e8065b1e3c673cc86348fb4e8154d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e7381a29eaecbe705d5189e52afd1332dd9acaf550036d2a6e289892d042c6b"

  strings:
    $s1  = "var UnZsGvh=function(){return WScript.CreateObject(nnvmxlUhCJFvcbwfDXuyc[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function TyVmNVQi(cnPvOKHADBDRWuzi,HUKnwyRliVlfdIMk){return cnPvOKHADBDRWuzi.charAt(HUKnwyRliVlfdIMk);}" fullword ascii
    $s3  = "function trQeyMjFgylhvv(OixrJfhzahekp) {var yZFbrErFnTSwnlLaFaw = tJVQwdWeiOPbmIkpgsMoIYT.join(nnvmxlUhCJFvcbwfDXuyc[7]);var wqt" ascii
    $s4  = "function FCSoHRCEn(){return WqdmtsNMXzhLP(nnvmxlUhCJFvcbwfDXuyc[9],[1,5,7],nnvmxlUhCJFvcbwfDXuyc[10]);}" fullword ascii
    $s5  = "function OIvUQ(SDijqGkUvVYG,LfRPCXqoArCBFtVwWq){return SDijqGkUvVYG.indexOf(LfRPCXqoArCBFtVwWq);}" fullword ascii
    $s6  = "function dVIxYVKoUacuHDZHkDWRvmX(wehQpGtVtOndfgPOPauX,NpmULVTibgpkErCIFEb){return String.fromCharCode(wehQpGtVtOndfgPOPauX,NpmUL" ascii
    $s7  = "function WqdmtsNMXzhLP(lnpiwVdJasR,QelmqwyGZTVfY,GKpUUkHDQqo){uUvnqxbPRP=lnpiwVdJasR.split(GKpUUkHDQqo);anYBb = nnvmxlUhCJFvcbwf" ascii
    $s8  = "(erMpIMQ,0x1,0x0)}function ytbsdinLrGC(NMQbYyd,WrvDrxoqDs,QYpmVwfQUfsL){var RqlnUJSjUMX=NMQbYyd.createtextfile(WrvDrxoqDs,true);" ascii
    $s9  = "function trOho(qjIIZGIWMBISDBvUOwfEn,cGsqniTFzFphEKQ,lRIUE){return String.fromCharCode(qjIIZGIWMBISDBvUOwfEn,cGsqniTFzFphEKQ,lRI" ascii
    $s10 = "jSzM, MfBSQlsbDUNKVBDbupMT);else TmOPt += trOho(wqtjSzM, MfBSQlsbDUNKVBDbupMT, VHGATGASWnvtIlJwei);} while (ikOICO < OixrJfhzahe" ascii
    $s11 = "fC & 0xff;if (elVJpchymjyIbPTdZskNB == 64) TmOPt += Qr(wqtjSzM);else if (SbqyTUwaUrC == 64) TmOPt += dVIxYVKoUacuHDZHkDWRvmX(wqt" ascii
    $s12 = "var UvwviZU=function(){return new ActiveXObject(nnvmxlUhCJFvcbwfDXuyc[1]);}();" fullword ascii
    $s13 = "function WqdmtsNMXzhLP(lnpiwVdJasR,QelmqwyGZTVfY,GKpUUkHDQqo){uUvnqxbPRP=lnpiwVdJasR.split(GKpUUkHDQqo);anYBb = nnvmxlUhCJFvcbwf" ascii
    $s14 = "(erMpIMQ,0x1,0x0)}function ytbsdinLrGC(NMQbYyd,WrvDrxoqDs,QYpmVwfQUfsL){var RqlnUJSjUMX=NMQbYyd.createtextfile(WrvDrxoqDs,true);" ascii
    $s15 = "kp.length);return TmOPt;}" fullword ascii
    $s16 = "function trOho(qjIIZGIWMBISDBvUOwfEn,cGsqniTFzFphEKQ,lRIUE){return String.fromCharCode(qjIIZGIWMBISDBvUOwfEn,cGsqniTFzFphEKQ,lRI" ascii
    $s17 = "function ifNmhVpZvsw(pQdKx,erMpIMQ) {var GKqrYOnt=[nnvmxlUhCJFvcbwfDXuyc[15]];pQdKx[GKqrYOnt[0]]" fullword ascii
    $s18 = "function dVIxYVKoUacuHDZHkDWRvmX(wehQpGtVtOndfgPOPauX,NpmULVTibgpkErCIFEb){return String.fromCharCode(wehQpGtVtOndfgPOPauX,NpmUL" ascii
    $s19 = "function Qr(ISoeVTbZcmAlPqCeNxTWXBq){return String.fromCharCode(ISoeVTbZcmAlPqCeNxTWXBq);}" fullword ascii
    $s20 = "function JYAdMeq(){return WqdmtsNMXzhLP(nnvmxlUhCJFvcbwfDXuyc[11],[2,4,8,10],nnvmxlUhCJFvcbwfDXuyc[12]);}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}