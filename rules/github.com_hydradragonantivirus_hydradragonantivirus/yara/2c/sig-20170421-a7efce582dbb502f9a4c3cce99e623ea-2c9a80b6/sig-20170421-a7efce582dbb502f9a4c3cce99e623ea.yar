rule sig_20170421_a7efce582dbb502f9a4c3cce99e623ea {
  meta:
    description = "datamaliciousorder - file 20170421_a7efce582dbb502f9a4c3cce99e623ea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f940052a671b543c234dd4b285916f1d2b5a4090dede385c41aab16f50e42881"

  strings:
    $s1 = "var rima = 10 * 50;" fullword ascii
    $s2 = "function ataaa(ziyter) {eval(ziyter);}" fullword ascii
    $s3 = "function muhter(kjg, lki) {return kjg.split(lki);}" fullword ascii
    $s4 = "function grohot(hunko,b1,b2,b3) {hunko.open(b1, b2, b3);}" fullword ascii
    $s5 = "var uuu = 0;while(uuu<999999) {uuu++;}" fullword ascii
    $s6 = "function fuuu(fuu1, fuu2) {return fuu1.join(fuu2);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}