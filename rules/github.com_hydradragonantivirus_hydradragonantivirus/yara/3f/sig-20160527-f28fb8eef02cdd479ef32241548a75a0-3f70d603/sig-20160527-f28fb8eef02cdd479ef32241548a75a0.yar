rule sig_20160527_f28fb8eef02cdd479ef32241548a75a0 {
  meta:
    description = "datamaliciousorder - file 20160527_f28fb8eef02cdd479ef32241548a75a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e6eb24b8c950af67de15c5cc17eea4122ea03dc814b4bd486a742df5292ef12"

  strings:
    $s1  = "function SnSvRtKRQeXgP() {return WScript;}function yOdcGN(){return BSOciiYuNjXR.ExpandEnvironmentStrings(NZIEx())}" fullword ascii
    $s2  = "function POpEUvrnPO(NBnSKlTBeBcRlXxp,pFAtQSjmIiajs){return NBnSKlTBeBcRlXxp.charAt(pFAtQSjmIiajs);}" fullword ascii
    $s3  = "mCharCode(92)+tTGnusRdHvUI[4],true);" fullword ascii
    $s4  = "var BSOciiYuNjXR=function(){return SnSvRtKRQeXgP().CreateObject(tTGnusRdHvUI[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s5  = ") bBcUlYGrkFYJwwFTDQnuWJk += jiuFSUBvunsNsslUBjQvBTr(HqIazMPWjgAmqGGglJBmi, dUajD);else bBcUlYGrkFYJwwFTDQnuWJk += DLSpuhyqYFYEi" ascii
    $s6  = "function DLSpuhyqYFYEiITLdfjMHT(vCdyhTUVaJVjjiHZnCrQBBLU,qOipdatBjksxcxbCn,OPrwRZ){return String.fromCharCode(vCdyhTUVaJVjjiHZnC" ascii
    $s7  = "function oCswvhFSJgXwXmY(fCmuxCczaWLlRd,uItnMjtUoRIhQmxMvFXVJZlJ){return fCmuxCczaWLlRd.indexOf(uItnMjtUoRIhQmxMvFXVJZlJ);}" fullword ascii
    $s8  = "function jiuFSUBvunsNsslUBjQvBTr(nuxCXY,qbSvuUDyQdy){return String.fromCharCode(nuxCXY,qbSvuUDyQdy);}" fullword ascii
    $s9  = "function JoQZRYg(){return ABGNcKBHWzpId(tTGnusRdHvUI[10],[2,4,8,10],tTGnusRdHvUI[11]);}" fullword ascii
    $s10 = "function Q(fufLJwDtenvddOwJlhFU){return String.fromCharCode(fufLJwDtenvddOwJlhFU);}" fullword ascii
    $s11 = "function ABGNcKBHWzpId(ZddGc,EhFBcNYJBJzZbY,hdlplqz){TeTIVvgl=ZddGc.split(hdlplqz);PtsjrvihMjhNAL = tTGnusRdHvUI[14];for(vJIGodc" ascii
    $s12 = "var vZsOQLoEmXQgVT = PSFAahiEny.createtextfile(BSOciiYuNjXR.ExpandEnvironmentStrings(tTGnusRdHvUI[2]+tTGnusRdHvUI[3])+String.fro" ascii
    $s13 = "var PSFAahiEny=function(){return new ActiveXObject(tTGnusRdHvUI[0]);}();" fullword ascii
    $s14 = "function NZIEx(){return ABGNcKBHWzpId(tTGnusRdHvUI[8],[1,5,7],tTGnusRdHvUI[9]);}" fullword ascii
    $s15 = "lG=0;vJIGodclG<EhFBcNYJBJzZbY.length;vJIGodclG++) {PtsjrvihMjhNAL+=TeTIVvgl[EhFBcNYJBJzZbY[vJIGodclG]];}return PtsjrvihMjhNAL.su" ascii
    $s16 = "AoJRsLXOsyUtnCSd & 0xff;if (kefMrDEjmRKRfP == 64) bBcUlYGrkFYJwwFTDQnuWJk += Q(HqIazMPWjgAmqGGglJBmi);else if (BOGZeRhouKX == 64" ascii
    $s17 = "function cZMrkACHgSLT(teeTLis,NEzykUZMKlhFD) {var KuzEwO=[tTGnusRdHvUI[15]];teeTLis[KuzEwO[0]](NEzykUZMKlhFD,0x1,0x0)}" fullword ascii
    $s18 = "function FOoICJel(tRocYAzmnBwEv) {var tVIJHnpTdXZeWSinzzVpBEz = RNTYXwkicvkyM.join(tTGnusRdHvUI[6]);var HqIazMPWjgAmqGGglJBmi, d" ascii
    $s19 = "ITLdfjMHT(HqIazMPWjgAmqGGglJBmi, dUajD, gueGhSGNJovxBaJmral);} while (ySCkJzLAgk < tRocYAzmnBwEv.length);return bBcUlYGrkFYJwwFT" ascii
    $s20 = "function DLSpuhyqYFYEiITLdfjMHT(vCdyhTUVaJVjjiHZnCrQBBLU,qOipdatBjksxcxbCn,OPrwRZ){return String.fromCharCode(vCdyhTUVaJVjjiHZnC" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}