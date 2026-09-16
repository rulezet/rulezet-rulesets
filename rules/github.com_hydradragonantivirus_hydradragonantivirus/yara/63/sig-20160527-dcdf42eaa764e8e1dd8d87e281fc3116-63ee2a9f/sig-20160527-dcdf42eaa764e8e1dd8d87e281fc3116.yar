rule sig_20160527_dcdf42eaa764e8e1dd8d87e281fc3116 {
  meta:
    description = "datamaliciousorder - file 20160527_dcdf42eaa764e8e1dd8d87e281fc3116.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ae28131c2184924bff31a8c10e8f8fba406cd176390a16ffb62415b2943149d2"

  strings:
    $s1  = "function FQIrmafj() {return WScript;}function IRXqbzvg(){return WhqSbjHLuEcb.ExpandEnvironmentStrings(gohhzredvoGBaz())}" fullword ascii
    $s2  = "function lKqZFHlCSaOOFUGLbP(sUqgxVhNzjwsGwd,FvrIOYjuqzD){return sUqgxVhNzjwsGwd.charAt(FvrIOYjuqzD);}" fullword ascii
    $s3  = "function gohhzredvoGBaz(){return bVgBrFJqCiwb(CeaqPPqYJKyq[8],[1,5,7],CeaqPPqYJKyq[9]);}" fullword ascii
    $s4  = "var vLjnlQAI = nMSkWMmEHfLUbb.createtextfile(WhqSbjHLuEcb.ExpandEnvironmentStrings(CeaqPPqYJKyq[2]+CeaqPPqYJKyq[3])+String.fromC" ascii
    $s5  = "function LFajjNvnQj(){return bVgBrFJqCiwb(CeaqPPqYJKyq[12],[0,3,6],CeaqPPqYJKyq[13]);}" fullword ascii
    $s6  = "function fKQqMoh(fVlSnIZfOZKl,rQSOG) {var eQrdV=[CeaqPPqYJKyq[15]];fVlSnIZfOZKl[eQrdV[0]](rQSOG,0x1,0x0)}" fullword ascii
    $s7  = "function BprvxIAwMQIOUv(bIZYEpzYjeJZbLqGrnEZD,iidvfCTOtJQWnOq){return String.fromCharCode(bIZYEpzYjeJZbLqGrnEZD,iidvfCTOtJQWnOq)" ascii
    $s8  = "function toMiVht(RhyVVARLthWaC) {var PMveuGFNS = DemVSBH.join(CeaqPPqYJKyq[6]);var tGjbNP, zimXNdpcOofdv, CwIcCEUsZVYgrRAWmjnnpr" ascii
    $s9  = "function BprvxIAwMQIOUv(bIZYEpzYjeJZbLqGrnEZD,iidvfCTOtJQWnOq){return String.fromCharCode(bIZYEpzYjeJZbLqGrnEZD,iidvfCTOtJQWnOq)" ascii
    $s10 = "var nMSkWMmEHfLUbb=function(){return new ActiveXObject(CeaqPPqYJKyq[0]);}();" fullword ascii
    $s11 = "f;CwIcCEUsZVYgrRAWmjnnpr = zbhpTxFHFIDD & 0xff;if (XLGmdXXvUSPRuZzRhyh == 64) KrfuOCSkqiJTG += KN(tGjbNP);else if (owfilsbjuXJdm" ascii
    $s12 = "function toMiVht(RhyVVARLthWaC) {var PMveuGFNS = DemVSBH.join(CeaqPPqYJKyq[6]);var tGjbNP, zimXNdpcOofdv, CwIcCEUsZVYgrRAWmjnnpr" ascii
    $s13 = "function bVgBrFJqCiwb(dvzYBvj,lqBmRfe,vcYgJhAnEm){bkzgD=dvzYBvj.split(vcYgJhAnEm);paEUxQ = CeaqPPqYJKyq[14];for(ThAlCoS=0;ThAlCo" ascii
    $s14 = "function IKNVqmGnv(RjHbST,cgmvAwX,rzvSEsHKiFngJZU){return String.fromCharCode(RjHbST,cgmvAwX,rzvSEsHKiFngJZU);}" fullword ascii
    $s15 = "S<lqBmRfe.length;ThAlCoS++) {paEUxQ+=bkzgD[lqBmRfe[ThAlCoS]];}return paEUxQ.substring(3,paEUxQ.length);}" fullword ascii
    $s16 = "var WhqSbjHLuEcb=function(){return FQIrmafj().CreateObject(CeaqPPqYJKyq[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s17 = "function zbayIkBUVfSFB(XsYILXDrlyULDcbKsKyQVZVh,PcMkrqHrPWGr){return XsYILXDrlyULDcbKsKyQVZVh.indexOf(PcMkrqHrPWGr);}" fullword ascii
    $s18 = "harCode(92)+CeaqPPqYJKyq[4],true);" fullword ascii
    $s19 = "function NAdovihMrm(){return bVgBrFJqCiwb(CeaqPPqYJKyq[10],[2,4,8,10],CeaqPPqYJKyq[11]);}" fullword ascii
    $s20 = "CEUsZVYgrRAWmjnnpr);} while (yvDmeUCMYUngQtHyxQN < RhyVVARLthWaC.length);return KrfuOCSkqiJTG;}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}