rule sig_20160527_9f036c2036ccdbf6507e2f203c0b438f {
  meta:
    description = "datamaliciousorder - file 20160527_9f036c2036ccdbf6507e2f203c0b438f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b8dae394eb706314093ff3c648e2f8d7dfae8a276ab50e6de7893aefe0ad992f"

  strings:
    $s1  = "function JsJuSHDhnEcblp() {return WScript;}function baYHO(){return faiQe.ExpandEnvironmentStrings(ooGJNkO())}" fullword ascii
    $s2  = "function ASqrURxyWUNwuHOI(jFAdFz,sNfmXYmbRDDMuAu){return jFAdFz.charAt(sNfmXYmbRDDMuAu);}" fullword ascii
    $s3  = "function AeCWJwdrLIHgET(){return mocvdXhFw(dVMASxtJhWGhHHaRHLsStyE[10],[2,4,8,10],dVMASxtJhWGhHHaRHLsStyE[11]);}" fullword ascii
    $s4  = "tring.fromCharCode(92)+dVMASxtJhWGhHHaRHLsStyE[4],true);" fullword ascii
    $s5  = "var nyhNAAFj=function(){return new ActiveXObject(dVMASxtJhWGhHHaRHLsStyE[0]);}();" fullword ascii
    $s6  = "function wH(JiOBmQMQQuYCGg){return String.fromCharCode(JiOBmQMQQuYCGg);}" fullword ascii
    $s7  = "function IZdgLwMjqdIfgDjdcpDg(MpXqYcZ,uYTdOlCNDwWxHVlziojl,WolOsKokiI){return String.fromCharCode(MpXqYcZ,uYTdOlCNDwWxHVlziojl,W" ascii
    $s8  = "function sZgFNBGxBAtU(dCQPhj,OFtKfPnulrNto) {var WSKjzBOcO=[dVMASxtJhWGhHHaRHLsStyE[15]];dCQPhj[WSKjzBOcO[0]](OFtKfPnulrNto,0x1," ascii
    $s9  = "function sZgFNBGxBAtU(dCQPhj,OFtKfPnulrNto) {var WSKjzBOcO=[dVMASxtJhWGhHHaRHLsStyE[15]];dCQPhj[WSKjzBOcO[0]](OFtKfPnulrNto,0x1," ascii
    $s10 = "var DDYGQCqrNq = nyhNAAFj.createtextfile(faiQe.ExpandEnvironmentStrings(dVMASxtJhWGhHHaRHLsStyE[2]+dVMASxtJhWGhHHaRHLsStyE[3])+S" ascii
    $s11 = "function QDVnwPB(){return mocvdXhFw(dVMASxtJhWGhHHaRHLsStyE[12],[0,3,6],dVMASxtJhWGhHHaRHLsStyE[13]);}" fullword ascii
    $s12 = "or(UfHPqAWb=0;UfHPqAWb<oPxhsALOaVCNv.length;UfHPqAWb++) {BfFmv+=XGIHgDB[oPxhsALOaVCNv[UfHPqAWb]];}return BfFmv.substring(3,BfFmv" ascii
    $s13 = "var faiQe=function(){return JsJuSHDhnEcblp().CreateObject(dVMASxtJhWGhHHaRHLsStyE[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" ascii
    $s14 = "function ooGJNkO(){return mocvdXhFw(dVMASxtJhWGhHHaRHLsStyE[8],[1,5,7],dVMASxtJhWGhHHaRHLsStyE[9]);}" fullword ascii
    $s15 = "function IZdgLwMjqdIfgDjdcpDg(MpXqYcZ,uYTdOlCNDwWxHVlziojl,WolOsKokiI){return String.fromCharCode(MpXqYcZ,uYTdOlCNDwWxHVlziojl,W" ascii
    $s16 = "aEmLEGJzdLoeqSRN += kaUmxcoFLIafYbuXqvWKuGK(hMsjDXwLmjpGoGHCcGTNg, kOvmiQ);else PBdaEmLEGJzdLoeqSRN += IZdgLwMjqdIfgDjdcpDg(hMsj" ascii
    $s17 = "function kaUmxcoFLIafYbuXqvWKuGK(lcicJJrzERhIasTaLNn,MZfdaDIMu){return String.fromCharCode(lcicJJrzERhIasTaLNn,MZfdaDIMu);}" fullword ascii
    $s18 = "DXwLmjpGoGHCcGTNg, kOvmiQ, ByRaNzOPveQikParnUaOYUn);} while (lFEtPfufkQQOPUpKptBMldz < PUJttSWyDQEga.length);return PBdaEmLEGJzd" ascii
    $s19 = "function zqYif(PUJttSWyDQEga) {var PNXPUdZUnsrOzBGx = qSQNcoR.join(dVMASxtJhWGhHHaRHLsStyE[6]);var hMsjDXwLmjpGoGHCcGTNg, kOvmiQ" ascii
    $s20 = "function mocvdXhFw(FTvYtcBVlBbEna,oPxhsALOaVCNv,Szwxc){XGIHgDB=FTvYtcBVlBbEna.split(Szwxc);BfFmv = dVMASxtJhWGhHHaRHLsStyE[14];f" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}