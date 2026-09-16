rule sig_20160527_c5604a8c33a9df8cb3824acbaa7dcc7d {
  meta:
    description = "datamaliciousorder - file 20160527_c5604a8c33a9df8cb3824acbaa7dcc7d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43772f80864debb6f725c2de1c4dfd7d64954a2d8959a9b49a357652d45a2e99"

  strings:
    $s1  = "function OcdTw() {return WScript;}function POaEY(){return OgJHDtIcZgbd.ExpandEnvironmentStrings(SZfwCyAfYxnP())}" fullword ascii
    $s2  = "function xSNIkQbtcKwfmUFUwAGaJYWz(PEuiGcrnkFPCXgsQfNxP,ftVbTVmczPbyESAcFqS){return PEuiGcrnkFPCXgsQfNxP.charAt(ftVbTVmczPbyESAcF" ascii
    $s3  = "function xSNIkQbtcKwfmUFUwAGaJYWz(PEuiGcrnkFPCXgsQfNxP,ftVbTVmczPbyESAcFqS){return PEuiGcrnkFPCXgsQfNxP.charAt(ftVbTVmczPbyESAcF" ascii
    $s4  = "var iyTbUnHDhfskD = SfGSGvzzJOVM.createtextfile(OgJHDtIcZgbd.ExpandEnvironmentStrings(jDbIiHT[2]+jDbIiHT[3])+String.fromCharCode" ascii
    $s5  = "(92)+jDbIiHT[4],true);" fullword ascii
    $s6  = "function SZfwCyAfYxnP(){return UHMvDdNGlg(jDbIiHT[8],[1,5,7],jDbIiHT[9]);}" fullword ascii
    $s7  = "function zDjvTuMyjpH(IIpQe,mtbpiBIinBOAFU) {var gRDpxZJBiuEX=[jDbIiHT[15]];IIpQe[gRDpxZJBiuEX[0]](mtbpiBIinBOAFU,0x1,0x0)}" fullword ascii
    $s8  = "function sVogY(yxrnZloiegHiB) {var stqrzDYw = WrlqKaT.join(jDbIiHT[6]);var ULyeFCfrEHEutkigkHW, qUQeGApHp, RrHXGjsrtwqqzOOHywEfU" ascii
    $s9  = "function rQxtQpZFY(IANieRUJigQ,URDezxqKigsTm){return IANieRUJigQ.indexOf(URDezxqKigsTm);}" fullword ascii
    $s10 = "var OgJHDtIcZgbd=function(){return OcdTw().CreateObject(jDbIiHT[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s11 = "function a(yzwstYePzgqeCihHgnnZN){return String.fromCharCode(yzwstYePzgqeCihHgnnZN);}" fullword ascii
    $s12 = "OYKAPKPY < yxrnZloiegHiB.length);return Kxvtl;}" fullword ascii
    $s13 = "function sVogY(yxrnZloiegHiB) {var stqrzDYw = WrlqKaT.join(jDbIiHT[6]);var ULyeFCfrEHEutkigkHW, qUQeGApHp, RrHXGjsrtwqqzOOHywEfU" ascii
    $s14 = "gkHW, qUQeGApHp);else Kxvtl += FgILnZStmzEKXGlvMXiAYNj(ULyeFCfrEHEutkigkHW, qUQeGApHp, RrHXGjsrtwqqzOOHywEfUEQ);} while (XAgYxFj" ascii
    $s15 = "gQmzuq<hVTkvcOY.length;ZgQmzuq++) {EhcEpHjPJvAph+=mURTlOCdUDScU[hVTkvcOY[ZgQmzuq]];}return EhcEpHjPJvAph.substring(3,EhcEpHjPJvA" ascii
    $s16 = " 0xff;if (tcdopgF == 64) Kxvtl += a(ULyeFCfrEHEutkigkHW);else if (mflPhuMxwguFroYuihwDYmb == 64) Kxvtl += EiVocL(ULyeFCfrEHEutki" ascii
    $s17 = "function UHMvDdNGlg(navns,hVTkvcOY,CHmltZukTL){mURTlOCdUDScU=navns.split(CHmltZukTL);EhcEpHjPJvAph = jDbIiHT[14];for(ZgQmzuq=0;Z" ascii
    $s18 = "function FgILnZStmzEKXGlvMXiAYNj(CviKZ,LOsWmgkCeSx,uhancgYMKpvd){return String.fromCharCode(CviKZ,LOsWmgkCeSx,uhancgYMKpvd);}" fullword ascii
    $s19 = "var SfGSGvzzJOVM=function(){return new ActiveXObject(jDbIiHT[0]);}();" fullword ascii
    $s20 = "function UHMvDdNGlg(navns,hVTkvcOY,CHmltZukTL){mURTlOCdUDScU=navns.split(CHmltZukTL);EhcEpHjPJvAph = jDbIiHT[14];for(ZgQmzuq=0;Z" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}