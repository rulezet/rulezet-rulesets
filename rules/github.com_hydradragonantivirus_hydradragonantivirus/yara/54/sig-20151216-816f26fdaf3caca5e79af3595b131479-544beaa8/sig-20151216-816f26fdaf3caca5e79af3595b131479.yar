rule sig_20151216_816f26fdaf3caca5e79af3595b131479 {
  meta:
    description = "datamaliciousorder - file 20151216_816f26fdaf3caca5e79af3595b131479.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6516bc31d6c8d659251ef09b42dbb6dc51c22889f76f0f04ce592362cfe17d7b"

  strings:
    $s1  = "th.pow(Math.cos(423), 2) - 1)); while(true) { if(FrBWaoEVc[QCNmzfsqZLS] > curQb[QCNmzfsqZLS].length-(-109+725)/616) { break; } i" ascii
    $s2  = ".pow(Math.cos(303), 2) - 1)));} FrBWaoEVc[QCNmzfsqZLS]++;}QCNmzfsqZLS++;} return yhcgsEnjivl}" fullword ascii
    $s3  = ") - 1));while(true){if (QCNmzfsqZLS >= (1034+652)/281){break;}FrBWaoEVc[QCNmzfsqZLS]=Math.round((Math.pow(Math.sin(423), 2) + Ma" ascii
    $s4  = "function mgKdJfKTTcxfqRIdg(curQb){yhcgsEnjivl= '';QCNmzfsqZLS=Math.round((Math.pow(Math.sin(819), 2) + Math.pow(Math.cos(819), 2" ascii
    $s5  = "PvOMvqrYczXyaihjouYZvIZgYXPhESUQlIyx([curQb[QCNmzfsqZLS][FrBWaoEVc[QCNmzfsqZLS]]], Math.round((Math.pow(Math.sin(303), 2) + Math" ascii
    $s6  = "function mgKdJfKTTcxfqRIdg(curQb){yhcgsEnjivl= '';QCNmzfsqZLS=Math.round((Math.pow(Math.sin(819), 2) + Math.pow(Math.cos(819), 2" ascii
    $s7  = "function uBDrbdD(gGftHLKTdROvQufPhSirjJmhecfXTWlmwylz) {return !NjVBucopVAg(fdfEkAMNSnjSaYr(gGftHLKTdROvQufPhSirjJmhecfXTWlmwylz" ascii
    $s8  = "g);return vWNSg;}" fullword ascii
    $s9  = "function DvJiGuvEbZxaBHv(PxAAOTSUzwiuTUOEc,tacgRsvDMjVIDIbdQZNSbQQoHLoAOuepxI,yskimovZpNOvCvzhJSFhAjAadWoSIzExoOy){eval(PxAAOTSU" ascii
    $s10 = "function p(RDaZXzAiXPjn,dyuhJKsBbKkUHh){RDaZXzAiXPjn.push(dyuhJKsBbKkUHh);}" fullword ascii
    $s11 = "function lFvAKKJPAAOF(kcsfxqFiUICwr) {return isFinite(kcsfxqFiUICwr);}" fullword ascii
    $s12 = "function BSuuM(cPwhdTCkXnE,WULjKOMMzRtUr,JPSEqmIg){fLMf=CjYynfzzRFEfKgdQa(cPwhdTCkXnE,WULjKOMMzRtUr);vWNSg=fLMf.toString(JPSEqmI" ascii
    $s13 = "function CjYynfzzRFEfKgdQa(ZsEvVtUnuv,cvFrYqksLU) {return parseInt(ZsEvVtUnuv,cvFrYqksLU);}" fullword ascii
    $s14 = "var B = new Array();B[0]=[];B[0][0]='d';B[0][1]='a';B[0][2]='d';B[0][3]='a';B[0][4]='46';B[0][5]='3d';B[0][6]='42';B[0][7]='14';" ascii
    $s15 = "function VnfkafQOnazEtkGCuzPvOMvqrYczXyaihjouYZvIZgYXPhESUQlIyx(XvjFAguSIAVwb,VSlEyQRSpxZDrr){ return pyTfVNt[zWimHbiz[BSuuM(Xvj" ascii
    $s16 = "function VnfkafQOnazEtkGCuzPvOMvqrYczXyaihjouYZvIZgYXPhESUQlIyx(XvjFAguSIAVwb,VSlEyQRSpxZDrr){ return pyTfVNt[zWimHbiz[BSuuM(Xvj" ascii
    $s17 = "function fdfEkAMNSnjSaYr(zTlraXhMhbxCWdZKHrD) {return parseFloat(zTlraXhMhbxCWdZKHrD);}" fullword ascii
    $s18 = "function Y(qKxCqRJopMUXGy,rxcEmZBQYuGrt,kzDnFWSUMNv) {qKxCqRJopMUXGy[rxcEmZBQYuGrt]=kzDnFWSUMNv;}" fullword ascii
    $s19 = "function DvJiGuvEbZxaBHv(PxAAOTSUzwiuTUOEc,tacgRsvDMjVIDIbdQZNSbQQoHLoAOuepxI,yskimovZpNOvCvzhJSFhAjAadWoSIzExoOy){eval(PxAAOTSU" ascii
    $s20 = "function NjVBucopVAg(twTYGgQsJqzttm) {return isNaN(twTYGgQsJqzttm);}" fullword ascii

  condition:
    uint16(0) == 0x577a and
    8 of them
}