rule sig_20160525_3b3e529dff2d264e7e77600348a62dd3 {
  meta:
    description = "datamaliciousorder - file 20160525_3b3e529dff2d264e7e77600348a62dd3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a0b487ce2e12da802282a6f72cc59849ee3ae008bafcd694e80dda5a8ce26cd"

  strings:
    $s1  = "155), 2) - 1))-561)) UpLeJEzdC += iPFVwluj(aPGpBhHSSCw, cXdDUhbavTXz);else UpLeJEzdC += afsRFbqZXGwdZ(aPGpBhHSSCw, cXdDUhbavTXz," ascii
    $s2  = "IsXstTWCmfTKMw(wCFjhuyGuZXJx,iUueljNmjAe++));JLHHcIDJNFZ = pdniY<< (308 + Math.round((Math.pow(Math.sin(350), 2) + Math.pow(Math" ascii
    $s3  = "function rqZLup(wCFjhuyGuZXJx) {var WEJXKzqjQbXWJPpQeFT = cKZnDWUOmaNfrGAWmTsdxcN.join(OaDndoINzuIZDcnuTwm[0]);var aPGpBhHSSCw, " ascii
    $s4  = ")-936)) UpLeJEzdC += Wg(aPGpBhHSSCw);else if (nXOFNbnXxxzj == (625 + Math.round((Math.pow(Math.sin(155), 2) + Math.pow(Math.cos(" ascii
    $s5  = "function afsRFbqZXGwdZ(fetlCJHySPhxpyiirC,FFswwAzLtYjReYDo,ZhRFWVtQvGFerBKymNg){return String.fromCharCode(fetlCJHySPhxpyiirC,FF" ascii
    $s6  = "function QSKIsXstTWCmfTKMw(OaqJshWfkwrmPrhLRhTmNXNO,hNtbLROBBWSGcGCSK){return OaqJshWfkwrmPrhLRhTmNXNO.charAt(hNtbLROBBWSGcGCSK)" ascii
    $s7  = "function afsRFbqZXGwdZ(fetlCJHySPhxpyiirC,FFswwAzLtYjReYDo,ZhRFWVtQvGFerBKymNg){return String.fromCharCode(fetlCJHySPhxpyiirC,FF" ascii
    $s8  = "function QSKIsXstTWCmfTKMw(OaqJshWfkwrmPrhLRhTmNXNO,hNtbLROBBWSGcGCSK){return OaqJshWfkwrmPrhLRhTmNXNO.charAt(hNtbLROBBWSGcGCSK)" ascii
    $s9  = "function rqZLup(wCFjhuyGuZXJx) {var WEJXKzqjQbXWJPpQeFT = cKZnDWUOmaNfrGAWmTsdxcN.join(OaDndoINzuIZDcnuTwm[0]);var aPGpBhHSSCw, " ascii
    $s10 = "function Wg(CCugeCWSIbhdA){return String.fromCharCode(CCugeCWSIbhdA);}" fullword ascii
    $s11 = "function GDkjTlNhseFHqdAI(UVPJynjo,etaNMIDNcxwl){return UVPJynjo.indexOf(etaNMIDNcxwl);}" fullword ascii
    $s12 = "function iPFVwluj(vCJJYoayF,osSPlYqowBCPUbzgeCNIerhO){return String.fromCharCode(vCJJYoayF,osSPlYqowBCPUbzgeCNIerhO);}" fullword ascii
    $s13 = " LeRNrCAoXaCuxyOMYiPcMhVO);} while (iUueljNmjAe < wCFjhuyGuZXJx.length);return UpLeJEzdC;}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}