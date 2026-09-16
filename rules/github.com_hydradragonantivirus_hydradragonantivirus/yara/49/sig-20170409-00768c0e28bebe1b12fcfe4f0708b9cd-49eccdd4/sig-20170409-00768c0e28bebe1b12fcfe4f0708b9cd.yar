rule sig_20170409_00768c0e28bebe1b12fcfe4f0708b9cd {
  meta:
    description = "datamaliciousorder - file 20170409_00768c0e28bebe1b12fcfe4f0708b9cd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ef984f5f484d590d6a5244071f41451a1161cca259807c6fdebbe939a98b98f"

  strings:
    $s1 = "var rima = 500;" fullword ascii
    $s2 = "function ataaa(ziyter) {eval(ziyter);}" fullword ascii
    $s3 = "function muhter(kjg, lki) {return kjg.split(lki);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}