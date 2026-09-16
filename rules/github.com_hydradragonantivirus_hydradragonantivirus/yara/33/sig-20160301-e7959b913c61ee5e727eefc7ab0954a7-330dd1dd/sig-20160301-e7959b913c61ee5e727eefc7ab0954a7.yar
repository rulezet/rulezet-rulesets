rule sig_20160301_e7959b913c61ee5e727eefc7ab0954a7 {
  meta:
    description = "datamaliciousorder - file 20160301_e7959b913c61ee5e727eefc7ab0954a7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e4a5135b3ff6c42eb95547ac3b30facf8366e827b6a2dbc3735689d0496ad48a"

  strings:
    $s1 = "while (cycleExtreme[(\"r\" + \"\\u0065a\\u0064\\u0079s\" + \"ta\\u0074\" + \"\\u0065\")] < ((100 + 0) / (1125 / 45))) {" fullword ascii
    $s2 = "0073\\u006f\\u0072\" + \"b\", function String.prototype.departmentStandard() {" fullword ascii
    $s3 = "extractDirective = jungleParity[(\"\\u0074u\\u006e\" + \"\\u006ee\\u006c\", \"\\u006f\" + \"p\\u0065\" + \"r\" + \"a\\u0074\" + " ascii
    $s4 = "scandalDiction = (1, this);" fullword ascii
    $s5 = "} catch (codePopular) {};" fullword ascii

  condition:
    uint16(0) == 0x6373 and
    all of them
}