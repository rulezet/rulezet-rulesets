rule sig_20160531_dfcf77fde7ba02cdfdcd04a9bd1cc2c3 {
  meta:
    description = "datamaliciousorder - file 20160531_dfcf77fde7ba02cdfdcd04a9bd1cc2c3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cfe6e6fc84c4c59ac88edf71f0de9fb445ebeac113c3b9e59af757726c056d1e"

  strings:
    $s1  = "var gTvBFcsqip=function(){return WScript.CreateObject(SYZjIXcglT[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function WyiEysKOwgnAjo(XDWlQHfwTauxKpz,UfRFCJtInquqMCMqusb){return XDWlQHfwTauxKpz.charAt(UfRFCJtInquqMCMqusb);}" fullword ascii
    $s3  = "function CrAfCpiWhLY(YrnBzUQsoj,nQQGGJMlTEf,HlolRT){ivwKa=YrnBzUQsoj.split(HlolRT);MSadHQdbJ = SYZjIXcglT[0];for(gebgsM=0;gebgsM" ascii
    $s4  = "function AUwPL(ljRkRpDQbwYTAoKgd,vjptOsCclrogCSKiuKbFQ){return String.fromCharCode(ljRkRpDQbwYTAoKgd,vjptOsCclrogCSKiuKbFQ);}" fullword ascii
    $s5  = "function QSIASyyzIsrpH(){return CrAfCpiWhLY(SYZjIXcglT[9],[1,5,7],SYZjIXcglT[10]);}" fullword ascii
    $s6  = "function KaARLfFyAlHSyfOXzwpZh(FgvsrHePWVx,lmYKVHRyTKftzQ){return FgvsrHePWVx.indexOf(lmYKVHRyTKftzQ);}" fullword ascii
    $s7  = "sPAiMPLPFan,true);SPxmNO.WriteLine(ATaUczKd);SPxmNO.Close();}" fullword ascii
    $s8  = "function ot(VvsCjbwbcMlAlyzIiNbpgR){return String.fromCharCode(VvsCjbwbcMlAlyzIiNbpgR);}" fullword ascii
    $s9  = "function LJAsSxYgmixsyR(DbFXeEdWaeZfL) {var xdPPRQDeESQGeWqFC = kTWhVxrPxtHlWvfPVyWrIqK.join(SYZjIXcglT[7]);var EyTnjGyYAxuDaTgH" ascii
    $s10 = "vMYFPQx, jzAAMveYJNKddPcVFgJf);} while (fpprAuPRKd < DbFXeEdWaeZfL.length);return xfFelUrdgyOAYMRbPPK;}" fullword ascii
    $s11 = "function krVOrGOaLp(QBZiYW,PSJmzOxVBUUDVm) {var RNsNp=[SYZjIXcglT[15]];QBZiYW[RNsNp[0]]" fullword ascii
    $s12 = "(PSJmzOxVBUUDVm,0x1,0x0)}function ArgYEtcvG(QSesyUtgJkfygC,ZChsPAiMPLPFan,ATaUczKd){var SPxmNO=QSesyUtgJkfygC.createtextfile(ZCh" ascii
    $s13 = "<nQQGGJMlTEf.length;gebgsM++) {MSadHQdbJ+=ivwKa[nQQGGJMlTEf[gebgsM]];}return MSadHQdbJ.substring(3,MSadHQdbJ.length);}" fullword ascii
    $s14 = "function nJOTobNjlDLhQQDlExzOnTcJ(cjtPSPtUMJdogCKh,UqjhgxwilLlLnTFWdU,KXHdKazrsc){return String.fromCharCode(cjtPSPtUMJdogCKh,Uq" ascii
    $s15 = "R & 0xff;if (eFRlyFgQpJUiLtrItltjAV == 64) xfFelUrdgyOAYMRbPPK += ot(EyTnjGyYAxuDaTgHG);else if (ITevXllzNYSwHt == 64) xfFelUrdg" ascii
    $s16 = "function CrAfCpiWhLY(YrnBzUQsoj,nQQGGJMlTEf,HlolRT){ivwKa=YrnBzUQsoj.split(HlolRT);MSadHQdbJ = SYZjIXcglT[0];for(gebgsM=0;gebgsM" ascii
    $s17 = "var IPCcBu=function(){return new ActiveXObject(SYZjIXcglT[1]);}();" fullword ascii
    $s18 = "function LJAsSxYgmixsyR(DbFXeEdWaeZfL) {var xdPPRQDeESQGeWqFC = kTWhVxrPxtHlWvfPVyWrIqK.join(SYZjIXcglT[7]);var EyTnjGyYAxuDaTgH" ascii
    $s19 = "function CJCKqmOsKteOM(){return CrAfCpiWhLY(SYZjIXcglT[13],[0,3,6],SYZjIXcglT[14]);}" fullword ascii
    $s20 = "function nJOTobNjlDLhQQDlExzOnTcJ(cjtPSPtUMJdogCKh,UqjhgxwilLlLnTFWdU,KXHdKazrsc){return String.fromCharCode(cjtPSPtUMJdogCKh,Uq" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}