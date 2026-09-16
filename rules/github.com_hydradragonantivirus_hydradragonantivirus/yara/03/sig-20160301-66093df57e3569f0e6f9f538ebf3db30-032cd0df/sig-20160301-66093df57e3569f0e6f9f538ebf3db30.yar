rule sig_20160301_66093df57e3569f0e6f9f538ebf3db30 {
  meta:
    description = "datamaliciousorder - file 20160301_66093df57e3569f0e6f9f538ebf3db30.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bfb24e074a9f07df09d9f82b6956d4c9b0e95f2fd41dc8d9a6156ac2dd67500e"

  strings:
    $s1 = "incidentFigure = (((1 + 0) | 0), this);" fullword ascii
    $s2 = "while (clanBar[(\"\\u006fb\" + \"l\" + \"\\u0069g\\u0061t\" + \"\\u0069\\u006f\\u006e\", \"\\u0063a\" + \"l\" + \"e\" + \"n\\u00" ascii
    $s3 = "while (clanBar[(\"\\u006fb\" + \"l\" + \"\\u0069g\\u0061t\" + \"\\u0069\\u006f\\u006e\", \"\\u0063a\" + \"l\" + \"e\" + \"n\\u00" ascii
    $s4 = "066t\\u0063\" + \"a\\u0072\\u0064s\\u002e\" + \"\\u0063\\u006fm\" + \"\\u002f3\\u002f\\u0036\" + \"7t\\u00354\\u0063\" + \"\\u00" ascii
    $s5 = "alphabetMile[(\"\\u0073\\u0063\" + \"\\u0061\\u006e\" + \"\\u0064al\", function String.prototype.supermanCertificate() {" fullword ascii
    $s6 = "} catch (liberalIdea) {};" fullword ascii

  condition:
    uint16(0) == 0x6e69 and
    all of them
}