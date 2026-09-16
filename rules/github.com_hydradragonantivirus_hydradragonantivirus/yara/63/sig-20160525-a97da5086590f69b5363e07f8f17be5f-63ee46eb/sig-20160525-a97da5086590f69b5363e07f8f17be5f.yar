rule sig_20160525_a97da5086590f69b5363e07f8f17be5f {
  meta:
    description = "datamaliciousorder - file 20160525_a97da5086590f69b5363e07f8f17be5f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8212a0a14c2dbb240fc5a413e3e34257cd11b5e752ad0a983506cb92f8c5a32f"

  strings:
    $s1  = " 2) + Math.pow(Math.cos(724), 2) - 1))-533)) ScuvsALyaJxhSQmUiRmVx += tP(yqAJCnhYvUSOJYmBmNHft);else if (AtcQixEnGAfUjQTFVhjA ==" ascii
    $s2  = "function SnGNbIY(dCpTtGABEAstY) {var bgghcyeLPggelZPSsHtH = aWDlPtGoObrhUslH.join(yFEPSUYXWbAujNR[0]);var yqAJCnhYvUSOJYmBmNHft," ascii
    $s3  = "function rniJmJKcrCEwyXjWDiqf(LvVCXjWvexQqYJSFffrLsaHC,DEhRpgooS){return LvVCXjWvexQqYJSFffrLsaHC.charAt(DEhRpgooS);}" fullword ascii
    $s4  = "function VAEGZSBryHLcdymWlU(arXFciixfgIWCuP,JjWpVkLiOJqFBqSwDtALecr){return String.fromCharCode(arXFciixfgIWCuP,JjWpVkLiOJqFBqSw" ascii
    $s5  = "XEmlLmf, MIIgOjKjNmnVmLDIoYgPXQNI);} while (fqAiwaGzGqhUQsTMY < dCpTtGABEAstY.length);return ScuvsALyaJxhSQmUiRmVx;}" fullword ascii
    $s6  = "WlU(yqAJCnhYvUSOJYmBmNHft, pHqPlJEInkUSFdnzXEmlLmf);else ScuvsALyaJxhSQmUiRmVx += cZEBVq(yqAJCnhYvUSOJYmBmNHft, pHqPlJEInkUSFdnz" ascii
    $s7  = "function VAEGZSBryHLcdymWlU(arXFciixfgIWCuP,JjWpVkLiOJqFBqSwDtALecr){return String.fromCharCode(arXFciixfgIWCuP,JjWpVkLiOJqFBqSw" ascii
    $s8  = "function cZEBVq(KbLHhFYvD,KwZdTtRzR,kbOFDyXgCxGyWfHMhxj){return String.fromCharCode(KbLHhFYvD,KwZdTtRzR,kbOFDyXgCxGyWfHMhxj);}" fullword ascii
    $s9  = "function tP(iZKrW){return String.fromCharCode(iZKrW);}" fullword ascii
    $s10 = "function SnGNbIY(dCpTtGABEAstY) {var bgghcyeLPggelZPSsHtH = aWDlPtGoObrhUslH.join(yFEPSUYXWbAujNR[0]);var yqAJCnhYvUSOJYmBmNHft," ascii
    $s11 = "function EgewoNaiFVB(uRactUBpVVrSV,ZUqOfVXHwfgsDrt){return uRactUBpVVrSV.indexOf(ZUqOfVXHwfgsDrt);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}