rule sig_20160301_c163eae05f103eca05c20bc47768e64d {
  meta:
    description = "datamaliciousorder - file 20160301_c163eae05f103eca05c20bc47768e64d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e2e6a4012b9aff2e72ccbaee28db6d1774810fca50e13edb5dcbc449f9f6ba42"

  strings:
    $s1 = "while (extremeConductor[(\"l\" + \"\\u0065ga\\u006c\", \"a\\u0063\" + \"\\u0063\\u006f\\u0072\\u0064\", \"\\u0063\" + \"e\\u006e" ascii
    $s2 = "while (extremeConductor[(\"l\" + \"\\u0065ga\\u006c\", \"a\\u0063\" + \"\\u0063\\u006f\\u0072\\u0064\", \"\\u0063\" + \"e\\u006e" ascii
    $s3 = "reanimationStimulus = (((1 * 1) * (15 - 14)), this);" fullword ascii
    $s4 = "  assortmentAlcohol[(\"a\" + \"rti\\u006cl\" + \"er\\u0079\", function String.prototype.translatorPacket() {" fullword ascii
    $s5 = "} catch (reporterMorphology) {};" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    all of them
}