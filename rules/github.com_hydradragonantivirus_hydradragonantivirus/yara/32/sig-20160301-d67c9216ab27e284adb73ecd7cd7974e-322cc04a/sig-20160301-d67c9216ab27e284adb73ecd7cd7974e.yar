rule sig_20160301_d67c9216ab27e284adb73ecd7cd7974e {
  meta:
    description = "datamaliciousorder - file 20160301_d67c9216ab27e284adb73ecd7cd7974e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9cc7c17b6ba22c5ab44e619b36d66c1ee60bc8c9bcb60355f07c00acfee1cdb5"

  strings:
    $s1 = "while (predicateLady[(\"del\\u0065\\u0067a\" + \"t\\u0069\\u006f\" + \"n\", \"\\u0062o\" + \"s\\u0073\", \"\\u0069\\u006dp\" + " ascii
    $s2 = "while (predicateLady[(\"del\\u0065\\u0067a\" + \"t\\u0069\\u006f\" + \"n\", \"\\u0062o\" + \"s\\u0073\", \"\\u0069\\u006dp\" + " ascii
    $s3 = "controlTunnel = occasionSponsor[(\"i\" + \"d\\u0065a\", \"\\u0061\\u0073\\u0073\\u006fr\" + \"\\u0074\\u006d\\u0065\\u006e\" + " ascii
    $s4 = "controlTunnel = occasionSponsor[(\"i\" + \"d\\u0065a\", \"\\u0061\\u0073\\u0073\\u006fr\" + \"\\u0074\\u006d\\u0065\\u006e\" + " ascii
    $s5 = "occasionSponsor = ((([+!+[]])), this);" fullword ascii
    $s6 = "} catch (blockInitiative) {};" fullword ascii

  condition:
    uint16(0) == 0x636f and
    all of them
}