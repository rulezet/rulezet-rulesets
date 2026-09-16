rule sig_20160530_cbc9d8c20c8a5393b90cec4581e103a1 {
  meta:
    description = "datamaliciousorder - file 20160530_cbc9d8c20c8a5393b90cec4581e103a1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f603af7193d1cadcba395afc46602e4def9d7eb2204b1c273fc24b48d81325a0"

  strings:
    $s1  = "var BgraXpvDo=function(){return WScript.CreateObject(pvTyxDFzEeNHlvN[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function eUkPzncihXCehqHp(KuboDeJcXqAesYq,BcESvRj){return KuboDeJcXqAesYq.charAt(BcESvRj);}" fullword ascii
    $s3  = "DQHJ);else if (btlJYMMMwg == 64) QmdMzg += KbiDzU(GMrDqGuCLAKAEShqSUjDQHJ, AigNLseEZnDnqYyNCsRteqP);else QmdMzg += CokZDxmFFgcNo" ascii
    $s4  = "function CokZDxmFFgcNonAMVeHJ(IGQDMaeGhKrLzAkVNoz,DHFww,QQbVFbuJXHDqxMwcuOFsyX){return String.fromCharCode(IGQDMaeGhKrLzAkVNoz,D" ascii
    $s5  = "function CokZDxmFFgcNonAMVeHJ(IGQDMaeGhKrLzAkVNoz,DHFww,QQbVFbuJXHDqxMwcuOFsyX){return String.fromCharCode(IGQDMaeGhKrLzAkVNoz,D" ascii
    $s6  = "function aXFvutjlR(MoMejoXqXMYDM) {var OlBZEnylgfXNWTrACUQL = aXOOnDavRWAmDjtXYl.join(pvTyxDFzEeNHlvN[7]);var GMrDqGuCLAKAEShqSU" ascii
    $s7  = "function KbiDzU(QQQRhONKXoOU,scjZPVqxLmveyBJVmn){return String.fromCharCode(QQQRhONKXoOU,scjZPVqxLmveyBJVmn);}" fullword ascii
    $s8  = "function aXFvutjlR(MoMejoXqXMYDM) {var OlBZEnylgfXNWTrACUQL = aXOOnDavRWAmDjtXYl.join(pvTyxDFzEeNHlvN[7]);var GMrDqGuCLAKAEShqSU" ascii
    $s9  = "var QNPprJXeMXBM=function(){return new ActiveXObject(pvTyxDFzEeNHlvN[1]);}();" fullword ascii
    $s10 = "function PZFpk(){return dlDfNg(pvTyxDFzEeNHlvN[13],[0,3,6],pvTyxDFzEeNHlvN[14]);}" fullword ascii
    $s11 = "arCode(92)+pvTyxDFzEeNHlvN[5],true);" fullword ascii
    $s12 = "function dlDfNg(LbjbkMFKpms,Ignhm,LuKhvAEXJZyCvV){jabgUGeKsj=LbjbkMFKpms.split(LuKhvAEXJZyCvV);RPXfSz = pvTyxDFzEeNHlvN[0];for(C" ascii
    $s13 = "function fWnsaaLxbeNH(BBTSRDzHnQJlHW,ZxePsfz) {var FiqWbi=[pvTyxDFzEeNHlvN[15]];BBTSRDzHnQJlHW[FiqWbi[0]]" fullword ascii
    $s14 = "function tB(oyPSaSAzYPykksThy){return String.fromCharCode(oyPSaSAzYPykksThy);}" fullword ascii
    $s15 = "biIgaJTvoBK=0;CbiIgaJTvoBK<Ignhm.length;CbiIgaJTvoBK++) {RPXfSz+=jabgUGeKsj[Ignhm[CbiIgaJTvoBK]];}return RPXfSz.substring(3,RPXf" ascii
    $s16 = "function NuPAHb(){return dlDfNg(pvTyxDFzEeNHlvN[9],[1,5,7],pvTyxDFzEeNHlvN[10]);}" fullword ascii
    $s17 = "function vOFAhEBOiWkYGSNtwQye(gmSMbwuWuPMoAtllopJqHlR,YaHWWsoQZFLROTjlC){return gmSMbwuWuPMoAtllopJqHlR.indexOf(YaHWWsoQZFLROTjl" ascii
    $s18 = "var aRxVXc = QNPprJXeMXBM.createtextfile(BgraXpvDo.ExpandEnvironmentStrings(pvTyxDFzEeNHlvN[3]+pvTyxDFzEeNHlvN[4])+String.fromCh" ascii
    $s19 = "function dlDfNg(LbjbkMFKpms,Ignhm,LuKhvAEXJZyCvV){jabgUGeKsj=LbjbkMFKpms.split(LuKhvAEXJZyCvV);RPXfSz = pvTyxDFzEeNHlvN[0];for(C" ascii
    $s20 = "function mwFlljXCvN(){return dlDfNg(pvTyxDFzEeNHlvN[11],[2,4,8,10],pvTyxDFzEeNHlvN[12]);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}