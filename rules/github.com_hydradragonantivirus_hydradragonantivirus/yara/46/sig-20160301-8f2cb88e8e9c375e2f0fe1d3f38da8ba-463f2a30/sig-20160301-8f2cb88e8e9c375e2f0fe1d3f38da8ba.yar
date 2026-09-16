rule sig_20160301_8f2cb88e8e9c375e2f0fe1d3f38da8ba {
  meta:
    description = "datamaliciousorder - file 20160301_8f2cb88e8e9c375e2f0fe1d3f38da8ba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b709003338b97c242b78c65d1eecca8fe67ce9afb16c257f576b8ed2c713bb24"

  strings:
    $s1 = "crisisArgument = (((0 & 1) + (15 - 14)), this);" fullword ascii
    $s2 = "]((\"o\\u0072\\u0067a\" + \"n\" + \"i\" + \"sm\", \"pre\" + \"t\\u0065ns\\u0069\" + \"\\u006f\\u006e\", function String.prototyp" ascii
    $s3 = "professionalJungle = crisisArgument[(\"at\" + \"ta\\u0063\\u006b\", \"\\u0068\\u0069\\u0073\\u0074o\" + \"r\" + \"\\u0079\", \"" ascii
    $s4 = "while (orientationFocus[(\"t\\u0065\\u0073t\", \"cu\" + \"\\u0062\\u0065\", \"\\u0072\\u0065\\u0061\\u0064y\" + \"\\u0073\\u0074" ascii
    $s5 = "while (orientationFocus[(\"t\\u0065\\u0073t\", \"cu\" + \"\\u0062\\u0065\", \"\\u0072\\u0065\\u0061\\u0064y\" + \"\\u0073\\u0074" ascii
    $s6 = "} catch (parallelClan) {};" fullword ascii

  condition:
    uint16(0) == 0x7263 and
    all of them
}