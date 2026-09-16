rule sig_20160525_a0546a91bdfaeae98216d7930a0504f4 {
  meta:
    description = "datamaliciousorder - file 20160525_a0546a91bdfaeae98216d7930a0504f4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2fa0357276284a62bf877e0b0e59cb243e7dede26a270c7742e6343bb8f4a809"

  strings:
    $s1  = "ath.pow(Math.sin(837), 2) + Math.pow(Math.cos(837), 2) - 1))-216) | NmRmTvGXD;qIURCWbliSwoJiGfZ = ksxCGGCcTylvcYV>> (338 + Math." ascii
    $s2  = "+= OLb(qIURCWbliSwoJiGfZ);else if (NmRmTvGXD == (247 + Math.round((Math.pow(Math.sin(804), 2) + Math.pow(Math.cos(804), 2) - 1))" ascii
    $s3  = "function zMhne(DSHnApDVdFnAr) {var GfRpuJCxxuquNzLuTBIHd = fgKwXsIWnhpNMNkTo.join(PGzuSEKiaRIHuFD[0]);var qIURCWbliSwoJiGfZ, pWH" ascii
    $s4  = "round((Math.pow(Math.sin(674), 2) + Math.pow(Math.cos(674), 2) - 1))-322) & 0xff;pWHArzcLztbQwiHzG = ksxCGGCcTylvcYV>> (162 + Ma" ascii
    $s5  = "function RxxCOvEFbBI(CrKEffwZSE,DguNFmwaDq){return CrKEffwZSE.charAt(DguNFmwaDq);}" fullword ascii
    $s6  = "function BSxVpHahSrotfFHwRznwEI(CWwyURAfrJhAyoRWXBhovXV,qjUcFgbdQ){return CWwyURAfrJhAyoRWXBhovXV.indexOf(qjUcFgbdQ);}" fullword ascii
    $s7  = "function JaEobAYKNkyuulSRHnQ(SsUogeWpKsQWgSh,NITkOToEwm,yadchYHXbkLeOjumrWIFOzv){return String.fromCharCode(SsUogeWpKsQWgSh,NITk" ascii
    $s8  = "function JaEobAYKNkyuulSRHnQ(SsUogeWpKsQWgSh,NITkOToEwm,yadchYHXbkLeOjumrWIFOzv){return String.fromCharCode(SsUogeWpKsQWgSh,NITk" ascii
    $s9  = "function OLb(jadpFLCW){return String.fromCharCode(jadpFLCW);}" fullword ascii
    $s10 = "function zMhne(DSHnApDVdFnAr) {var GfRpuJCxxuquNzLuTBIHd = fgKwXsIWnhpNMNkTo.join(PGzuSEKiaRIHuFD[0]);var qIURCWbliSwoJiGfZ, pWH" ascii
    $s11 = "function NJdnvh(NwuvXFeTSozIXa,ySZWncJkICkBMIUggB){return String.fromCharCode(NwuvXFeTSozIXa,ySZWncJkICkBMIUggB);}" fullword ascii
    $s12 = "-183)) bAXVLtvgNpG += NJdnvh(qIURCWbliSwoJiGfZ, pWHArzcLztbQwiHzG);else bAXVLtvgNpG += JaEobAYKNkyuulSRHnQ(qIURCWbliSwoJiGfZ, pW" ascii
    $s13 = "HArzcLztbQwiHzG, OmjPjtTXxCMoCBmFMjnfyAy);} while (jTwrZIDOuHQQPkFuf < DSHnApDVdFnAr.length);return bAXVLtvgNpG;}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}