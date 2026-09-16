rule sig_20151216_c73c0ea657f6c7c1af90c493b02e73d9 {
  meta:
    description = "datamaliciousorder - file 20151216_c73c0ea657f6c7c1af90c493b02e73d9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33759b7a5ad3d9e507adb070cde6887baf14e280639b598596bf5b4dc04d0973"

  strings:
    $s1  = ") - 1));while(true){if (ZuJidOzRBVF >= (-495+813)/53){break;}lpCPaTugy[ZuJidOzRBVF]=Math.round((Math.pow(Math.sin(929), 2) + Mat" ascii
    $s2  = "h.pow(Math.cos(929), 2) - 1)); while(true) { if(lpCPaTugy[ZuJidOzRBVF] > kTHzD[ZuJidOzRBVF].length-(-49+706)/657) { break; } if " ascii
    $s3  = "function qpfaIBNLyStiPIkqp(kTHzD){zKLFRnnWXxI= '';ZuJidOzRBVF=Math.round((Math.pow(Math.sin(801), 2) + Math.pow(Math.cos(801), 2" ascii
    $s4  = "w(Math.cos(948), 2) - 1)));} lpCPaTugy[ZuJidOzRBVF]++;}ZuJidOzRBVF++;} return zKLFRnnWXxI}" fullword ascii
    $s5  = "function qpfaIBNLyStiPIkqp(kTHzD){zKLFRnnWXxI= '';ZuJidOzRBVF=Math.round((Math.pow(Math.sin(801), 2) + Math.pow(Math.cos(801), 2" ascii
    $s6  = "function BTpobXR(IHFqtEgyWCeuSymvHyWFlxSquHUiimOoxEoB) {return !PgRqcIPGQNq(VbnVMnIQsYVncpO(IHFqtEgyWCeuSymvHyWFlxSquHUiimOoxEoB" ascii
    $s7  = "var l = new Array();l[0]=[];l[0][0]='d';l[0][1]='a';l[0][2]='d';l[0][3]='a';l[0][4]='46';l[0][5]='3d';l[0][6]='42';l[0][7]='14';" ascii
    $s8  = "function ecixErxUEiWujXYSQblecUpSRAaAgQUwTWeZaPUSfJxdknhVmmkvhb(StZKDABrNDxbh,aCCXNcwBtwWRrB){ return XoPiYzK[BkGRXXPI[XQZhG(StZ" ascii
    $s9  = "function k(pIvPeGCHiFcs,sbXtskmbUDDoDf){pIvPeGCHiFcs.push(sbXtskmbUDDoDf);}" fullword ascii
    $s10 = "function rbIoSyOGykwP(xJHAeDHPeCkyQ) {return isFinite(xJHAeDHPeCkyQ);}" fullword ascii
    $s11 = "function ecixErxUEiWujXYSQblecUpSRAaAgQUwTWeZaPUSfJxdknhVmmkvhb(StZKDABrNDxbh,aCCXNcwBtwWRrB){ return XoPiYzK[BkGRXXPI[XQZhG(StZ" ascii
    $s12 = "var l = new Array();l[0]=[];l[0][0]='d';l[0][1]='a';l[0][2]='d';l[0][3]='a';l[0][4]='46';l[0][5]='3d';l[0][6]='42';l[0][7]='14';" ascii
    $s13 = "f);return tomla;}" fullword ascii
    $s14 = "function BTpobXR(IHFqtEgyWCeuSymvHyWFlxSquHUiimOoxEoB) {return !PgRqcIPGQNq(VbnVMnIQsYVncpO(IHFqtEgyWCeuSymvHyWFlxSquHUiimOoxEoB" ascii
    $s15 = "function XQZhG(OamOhQjpcCh,MucjIMSFxbldC,FeVEsvuf){Efhd=fNKBxCsdwHbGeVhlH(OamOhQjpcCh,MucjIMSFxbldC);tomla=Efhd.toString(FeVEsvu" ascii
    $s16 = "function fNKBxCsdwHbGeVhlH(yHSapRNlXv,LzgRjUjkSQ) {return parseInt(yHSapRNlXv,LzgRjUjkSQ);}" fullword ascii
    $s17 = "function lkuGSoWoiUlrCEe(AOquGDQWiQnifUeXb,ZNnABEiIHKtCsFXOQFBEtoyIEVmDOwxqoY,MCZDUgsAItJAaJcGoFIealXbwtwSpTJaMEf){eval(AOquGDQW" ascii
    $s18 = "function lkuGSoWoiUlrCEe(AOquGDQWiQnifUeXb,ZNnABEiIHKtCsFXOQFBEtoyIEVmDOwxqoY,MCZDUgsAItJAaJcGoFIealXbwtwSpTJaMEf){eval(AOquGDQW" ascii
    $s19 = "function XQZhG(OamOhQjpcCh,MucjIMSFxbldC,FeVEsvuf){Efhd=fNKBxCsdwHbGeVhlH(OamOhQjpcCh,MucjIMSFxbldC);tomla=Efhd.toString(FeVEsvu" ascii
    $s20 = "function PgRqcIPGQNq(bWvGCruKAeHItm) {return isNaN(bWvGCruKAeHItm);}" fullword ascii

  condition:
    uint16(0) == 0x6b42 and
    8 of them
}