rule sig_20160527_216f2a634e10edea6d460038b3183b2d {
  meta:
    description = "datamaliciousorder - file 20160527_216f2a634e10edea6d460038b3183b2d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c2d7021ea6ab6593586b1881107f06bf34b6df5b6a3de5a3290f8da21ffb33b"

  strings:
    $s1  = "function gRnsiOZVUIZb() {return WScript;}function qXkFhM(){return difdxTAA.ExpandEnvironmentStrings(GatZmutFTe())}" fullword ascii
    $s2  = "function iDvmRbTBteFWe(vXZLYYsKezeJWicyolCWicpy,QqrdImzUhBUGLwLPrmUCiOY){return vXZLYYsKezeJWicyolCWicpy.charAt(QqrdImzUhBUGLwLP" ascii
    $s3  = "function iDvmRbTBteFWe(vXZLYYsKezeJWicyolCWicpy,QqrdImzUhBUGLwLPrmUCiOY){return vXZLYYsKezeJWicyolCWicpy.charAt(QqrdImzUhBUGLwLP" ascii
    $s4  = "function VFtiOPjPaSFts(GaHSIvNgPXqowUvWWbA,eIveiKAZiMUSenoKg){return GaHSIvNgPXqowUvWWbA.indexOf(eIveiKAZiMUSenoKg);}" fullword ascii
    $s5  = "function TppOsUe(QTKSYi,JuHymCdLOfSR) {var ZiaZBzZlx=[cJZvLCrzjNVhLEFJ[15]];QTKSYi[ZiaZBzZlx[0]](JuHymCdLOfSR,0x1,0x0)}" fullword ascii
    $s6  = "function ucUBmHQV(){return feNzWhTiQnajqJ(cJZvLCrzjNVhLEFJ[10],[2,4,8,10],cJZvLCrzjNVhLEFJ[11]);}" fullword ascii
    $s7  = "var PNhCTBrNLVC=function(){return new ActiveXObject(cJZvLCrzjNVhLEFJ[0]);}();" fullword ascii
    $s8  = "function feNzWhTiQnajqJ(NYUGPmBtAZbsBj,ylKxmcgYhAgE,kGvwPGTyMBLSr){nvjGrfMttA=NYUGPmBtAZbsBj.split(kGvwPGTyMBLSr);ofLBTvaDV = cJ" ascii
    $s9  = "var difdxTAA=function(){return gRnsiOZVUIZb().CreateObject(cJZvLCrzjNVhLEFJ[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s10 = "function QZkkxbRTcgBTyDNDC(BOzgYmsHEaJhGZQUcEwj,ONSOG){return String.fromCharCode(BOzgYmsHEaJhGZQUcEwj,ONSOG);}" fullword ascii
    $s11 = "xznydJZFhAWdgZf += gJyfyUEj(eABMKnIl, hJCeF, sMOnxoLwQSdWPBlddxOQN);} while (MgsWFkWkmeMw < RhufNmnppLffU.length);return dhBbpND" ascii
    $s12 = "function feNzWhTiQnajqJ(NYUGPmBtAZbsBj,ylKxmcgYhAgE,kGvwPGTyMBLSr){nvjGrfMttA=NYUGPmBtAZbsBj.split(kGvwPGTyMBLSr);ofLBTvaDV = cJ" ascii
    $s13 = "function UTytBonrmkegc(RhufNmnppLffU) {var SQiPvcUQEdzWaKLNaefGil = OiOSY.join(cJZvLCrzjNVhLEFJ[6]);var eABMKnIl, hJCeF, sMOnxoL" ascii
    $s14 = "[iWahazbqUFFgZW]];}return ofLBTvaDV.substring(3,ofLBTvaDV.length);}" fullword ascii
    $s15 = "function UTytBonrmkegc(RhufNmnppLffU) {var SQiPvcUQEdzWaKLNaefGil = OiOSY.join(cJZvLCrzjNVhLEFJ[6]);var eABMKnIl, hJCeF, sMOnxoL" ascii
    $s16 = "var LVhzSc = PNhCTBrNLVC.createtextfile(difdxTAA.ExpandEnvironmentStrings(cJZvLCrzjNVhLEFJ[2]+cJZvLCrzjNVhLEFJ[3])+String.fromCh" ascii
    $s17 = "function GatZmutFTe(){return feNzWhTiQnajqJ(cJZvLCrzjNVhLEFJ[8],[1,5,7],cJZvLCrzjNVhLEFJ[9]);}" fullword ascii
    $s18 = "DxznydJZFhAWdgZf += t(eABMKnIl);else if (JIhFEK == 64) dhBbpNDxznydJZFhAWdgZf += QZkkxbRTcgBTyDNDC(eABMKnIl, hJCeF);else dhBbpND" ascii
    $s19 = "arCode(92)+cJZvLCrzjNVhLEFJ[4],true);" fullword ascii
    $s20 = "function t(oZVAJcXDPEtV){return String.fromCharCode(oZVAJcXDPEtV);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}