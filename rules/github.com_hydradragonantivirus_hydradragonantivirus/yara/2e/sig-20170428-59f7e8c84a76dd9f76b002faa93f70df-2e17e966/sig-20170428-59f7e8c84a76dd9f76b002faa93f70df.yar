rule sig_20170428_59f7e8c84a76dd9f76b002faa93f70df {
  meta:
    description = "datamaliciousorder - file 20170428_59f7e8c84a76dd9f76b002faa93f70df.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "385026a8f7f83f3949f08cf9003185be4f168878524009e103f310fc30302b3f"

  strings:
    $s1 = "var rima = 10 * 50;" fullword ascii
    $s2 = "function grohot(hunko,b1,b2,b3) {hunko.open(b1, b2, b3);}" fullword ascii
    $s3 = "function fuuu(fuu1, fuu2) {return fuu1.join(fuu2);}" fullword ascii
    $s4 = "var uuu = 10;while(uuu<999999) {uuu++;}" fullword ascii
    $s5 = "function ataaa(ziyter) {eval(ziyter+'');}" fullword ascii
    $s6 = "function muhter(kjg, lki) {return kjg.split(lki+'');}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}