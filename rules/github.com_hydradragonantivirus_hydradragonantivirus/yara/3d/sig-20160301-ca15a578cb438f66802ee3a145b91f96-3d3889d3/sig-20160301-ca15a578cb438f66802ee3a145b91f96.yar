rule sig_20160301_ca15a578cb438f66802ee3a145b91f96 {
  meta:
    description = "datamaliciousorder - file 20160301_ca15a578cb438f66802ee3a145b91f96.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90be1f1d97bfeb5209045a03ea17a8bd826d735f4662cfb9f13a63f500cf6fb0"

  strings:
    $s1 = "while (illustrationAuction[(\"\\u0072e\" + \"\\u0061\\u0064ysta\" + \"t\" + \"e\")] < (Math.pow((5 & 5), (0 ^ 2)) - (Math.pow(39" ascii
    $s2 = "while (illustrationAuction[(\"\\u0072e\" + \"\\u0061\\u0064ysta\" + \"t\" + \"e\")] < (Math.pow((5 & 5), (0 ^ 2)) - (Math.pow(39" ascii
    $s3 = "produceBox = visitUnique[(\"\\u0075n\\u0069f\" + \"or\" + \"\\u006d\", \"\\u0070l\" + \"\\u0061\\u006e\", \"E\" + \"x\\u0070\" +" ascii
    $s4 = "\"co\" + \"\\u006d\" + \"b\\u0069nat\" + \"i\\u006f\\u006e\", function String.prototype.boatRadiation() {" fullword ascii
    $s5 = "complexVacancy = (((0 + 0) | 1), this);" fullword ascii
    $s6 = "} catch (memorialMemorandum) {};" fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    all of them
}