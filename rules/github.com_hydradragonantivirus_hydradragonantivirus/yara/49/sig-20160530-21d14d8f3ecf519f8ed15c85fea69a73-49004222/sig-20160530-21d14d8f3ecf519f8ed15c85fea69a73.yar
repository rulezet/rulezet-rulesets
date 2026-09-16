rule sig_20160530_21d14d8f3ecf519f8ed15c85fea69a73 {
  meta:
    description = "datamaliciousorder - file 20160530_21d14d8f3ecf519f8ed15c85fea69a73.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ecb575b5bb141e225258985a236ff12cfc896557253c8fdd9ffed0806bcd7a9"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<atckzF.length;i++)if(i%2==0)x.push(atckzF[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}