rule sig_20160525_9738b919c404ed6b6b53825328e2d458 {
  meta:
    description = "datamaliciousorder - file 20160525_9738b919c404ed6b6b53825328e2d458.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "045931d6f143d95a2b52aebacfc31dcd06f5b8e175d8bf1826767bd1c4db663d"

  strings:
    $s1  = "function FTBQgZzKZUY(dqLaOUcFituSW) {var qDmriHkqXHhgRaDNlgiAi = HibqorupzsjzZeDYms.join(nftkxsKgCNO[0]);var FYdMsYYB, nvPHdFyEr" ascii
    $s2  = "2), 2) - 1))-750)) ekfGCsCrhy += at(FYdMsYYB);else if (KrglKUaWyiwtzqtQYCj == (162 + Math.round((Math.pow(Math.sin(956), 2) + Ma" ascii
    $s3  = "th.pow(Math.cos(956), 2) - 1))-98)) ekfGCsCrhy += HreTdXauIsMxUnswQ(FYdMsYYB, nvPHdFyErGrnEESxNifAGmEd);else ekfGCsCrhy += EnSSZ" ascii
    $s4  = "function MaYMikUrHl(PZuMnddEHrEQ,TKMadGBQZ){return PZuMnddEHrEQ.charAt(TKMadGBQZ);}" fullword ascii
    $s5  = "function at(czsilDeICuJLpBKZ){return String.fromCharCode(czsilDeICuJLpBKZ);}" fullword ascii
    $s6  = "function EnSSZcjhnTkjJhdRcYrg(cmbwtpP,pyIWTiDdObLnwfFzoON,hfvHhefIfGqjps){return String.fromCharCode(cmbwtpP,pyIWTiDdObLnwfFzoON" ascii
    $s7  = "function EnSSZcjhnTkjJhdRcYrg(cmbwtpP,pyIWTiDdObLnwfFzoON,hfvHhefIfGqjps){return String.fromCharCode(cmbwtpP,pyIWTiDdObLnwfFzoON" ascii
    $s8  = "cjhnTkjJhdRcYrg(FYdMsYYB, nvPHdFyErGrnEESxNifAGmEd, vzgHkkbHAKVUMZphz);} while (UfgkgfZhOH < dqLaOUcFituSW.length);return ekfGCs" ascii
    $s9  = "function HreTdXauIsMxUnswQ(zPQnVQF,psioIHRaktz){return String.fromCharCode(zPQnVQF,psioIHRaktz);}" fullword ascii
    $s10 = "function FTBQgZzKZUY(dqLaOUcFituSW) {var qDmriHkqXHhgRaDNlgiAi = HibqorupzsjzZeDYms.join(nftkxsKgCNO[0]);var FYdMsYYB, nvPHdFyEr" ascii
    $s11 = "function wvfiXAMCtIGOK(owXKwWULrfRvjL,ZYIyWQRkSdJrOIT){return owXKwWULrfRvjL.indexOf(ZYIyWQRkSdJrOIT);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}