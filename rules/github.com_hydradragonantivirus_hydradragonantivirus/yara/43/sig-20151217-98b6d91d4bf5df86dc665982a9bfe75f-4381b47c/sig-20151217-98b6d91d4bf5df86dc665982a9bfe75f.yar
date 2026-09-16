rule sig_20151217_98b6d91d4bf5df86dc665982a9bfe75f {
  meta:
    description = "datamaliciousorder - file 20151217_98b6d91d4bf5df86dc665982a9bfe75f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "04bdde9c6f5ba55287dae40834a44aeb5b0c589290abf24cd0ace3531352abe3"

  strings:
    $s1  = "w(Math.cos(519), 2) - 1)));} JRbbwnmfR[yaefQcnkqIv]++;}yaefQcnkqIv++;} return mwwzbCptSVs}" fullword ascii
    $s2  = "th.pow(Math.cos(964), 2) - 1)); while(true) { if(JRbbwnmfR[yaefQcnkqIv] > eARNj[yaefQcnkqIv].length-(-84+584)/500) { break; } if" ascii
    $s3  = ") - 1));while(true){if (yaefQcnkqIv >= (2518+374)/482){break;}JRbbwnmfR[yaefQcnkqIv]=Math.round((Math.pow(Math.sin(964), 2) + Ma" ascii
    $s4  = "function EtJJQFxToiChpMUfW(eARNj){mwwzbCptSVs= '';yaefQcnkqIv=Math.round((Math.pow(Math.sin(908), 2) + Math.pow(Math.cos(908), 2" ascii
    $s5  = "function EtJJQFxToiChpMUfW(eARNj){mwwzbCptSVs= '';yaefQcnkqIv=Math.round((Math.pow(Math.sin(908), 2) + Math.pow(Math.cos(908), 2" ascii
    $s6  = "function QSRVhdr(GVMgbvaTaTGdkPIljwUabJOTepygQMcUKWfI) {return !XeHJGQsTFIz(iekVDIJuSZDEkzJ(GVMgbvaTaTGdkPIljwUabJOTepygQMcUKWfI" ascii
    $s7  = "var L = new Array();L[0]=[];L[0][0]='d';L[0][1]='a';L[0][2]='d';L[0][3]='a';L[0][4]='46';L[0][5]='3d';L[0][6]='42';L[0][7]='14';" ascii
    $s8  = "function iekVDIJuSZDEkzJ(uGzJpgnnbZPEgIBFVro) {return parseFloat(uGzJpgnnbZPEgIBFVro);}" fullword ascii
    $s9  = "function F(xNNRwLgAKKNL,ijRaHlMOttHFcT){xNNRwLgAKKNL.push(ijRaHlMOttHFcT);}" fullword ascii
    $s10 = "function Hnobl(QZbvbAKWVGM,GvcCqjkykqQPm,KblutZfJ){MQfG=xBbWWZRzYnvUrAHpn(QZbvbAKWVGM,GvcCqjkykqQPm);foZbT=MQfG.toString(KblutZf" ascii
    $s11 = "function xBbWWZRzYnvUrAHpn(wcTBBoSqCi,cUGMGfrOcz) {return parseInt(wcTBBoSqCi,cUGMGfrOcz);}" fullword ascii
    $s12 = "J);return foZbT;}" fullword ascii
    $s13 = "var L = new Array();L[0]=[];L[0][0]='d';L[0][1]='a';L[0][2]='d';L[0][3]='a';L[0][4]='46';L[0][5]='3d';L[0][6]='42';L[0][7]='14';" ascii
    $s14 = "function Hnobl(QZbvbAKWVGM,GvcCqjkykqQPm,KblutZfJ){MQfG=xBbWWZRzYnvUrAHpn(QZbvbAKWVGM,GvcCqjkykqQPm);foZbT=MQfG.toString(KblutZf" ascii
    $s15 = "function icRGYhvRGIXN(qlTKoLUOBUczI) {return isFinite(qlTKoLUOBUczI);}" fullword ascii
    $s16 = "function QSRVhdr(GVMgbvaTaTGdkPIljwUabJOTepygQMcUKWfI) {return !XeHJGQsTFIz(iekVDIJuSZDEkzJ(GVMgbvaTaTGdkPIljwUabJOTepygQMcUKWfI" ascii
    $s17 = "function XDZssYIjhUyDgfumQMfODKrzgwASuWxgGYFdbItMEsxrKzFSLYmLrA(MntKFjDlUvEkg,ecNwGwoOqiORRc){ return MsyKvDc[kgAFisME[Hnobl(Mnt" ascii
    $s18 = "function XeHJGQsTFIz(VTaoqMVDroeNcW) {return isNaN(VTaoqMVDroeNcW);}" fullword ascii
    $s19 = "function zpctkvQivHOBuIB(yLxnIDWSuBUryKlaQ,gyweEOGvPmHKSzTztBHTgSfHAJgpmuLSOy,zqinWyfdimbUgrSVAoSdOtkMMxrAyauPwbH){eval(yLxnIDWS" ascii
    $s20 = "function zpctkvQivHOBuIB(yLxnIDWSuBUryKlaQ,gyweEOGvPmHKSzTztBHTgSfHAJgpmuLSOy,zqinWyfdimbUgrSVAoSdOtkMMxrAyauPwbH){eval(yLxnIDWS" ascii

  condition:
    uint16(0) == 0x676b and
    8 of them
}