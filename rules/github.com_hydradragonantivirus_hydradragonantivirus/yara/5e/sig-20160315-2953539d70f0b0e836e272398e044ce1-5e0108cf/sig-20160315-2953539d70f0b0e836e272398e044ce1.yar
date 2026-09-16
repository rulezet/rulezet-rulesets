rule sig_20160315_2953539d70f0b0e836e272398e044ce1 {
  meta:
    description = "datamaliciousorder - file 20160315_2953539d70f0b0e836e272398e044ce1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f5fd4abd1511453cf740d35ee5bbb415a4608f1a67f162dea19c4eeb58df97f9"

  strings:
    $s1 = "function nfnNgBUFMmIxiGp(ylceFFtIKvPd){WshShell[EGAcVBqHKALD + jVVZwWe](ylceFFtIKvPd, 0, 0);}" fullword ascii
    $s2 = "while (uHXcerVx.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "function QCqFKyol(n){return DDjVF + HJTCLsYWCj + kqTfjcUzM + Pzbc + zwIXftBoE + EzJOeDPffShEdcL;}" fullword ascii
    $s4 = "uHXcerVx[gfFGtUPXOSNqY + Fzt](GFDYuacVSH + UujoraWAnaGUu, WRxaBMjSDsiVpr + pWW + QqZGuVFUl + PdUiBElVPvzpFgJ + BeSLaGp + gkvkVUu" ascii
    $s5 = "YMg + HjLkI + JOsE + eXqmLOtChxM + mRXmQHWFYwu + JWqzhoe + uTYnYvKMiNVqX + pCQCAMI + LhdpTCDhViuHMrm + XgLT, false);" fullword ascii
    $s6 = "var itJ = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}