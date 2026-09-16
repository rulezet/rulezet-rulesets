rule sig_20160301_ea42377a0dc28c04746860f35d5312ef {
  meta:
    description = "datamaliciousorder - file 20160301_ea42377a0dc28c04746860f35d5312ef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b83f7be3795d0c9df4b9a73acb341f7aecffe0b899c546aec62746d1767a024"

  strings:
    $s1 = "while (primitiveTandem[(\"t\" + \"ech\" + \"n\\u0069\\u0071u\\u0065\", \"\\u0074\\u0065l\" + \"e\\u0076i\" + \"\\u0073\" + \"\\u" ascii
    $s2 = "scandalBlock[(\"r\\u0065\\u0067\\u0075\\u006c\" + \"\\u0061\\u0074e\", \"\\u0066\\u0061\\u0063ade\", \"\\u0063\\u006f\" + \"mple" ascii
    $s3 = "scandalBlock[(\"r\\u0065\\u0067\\u0075\\u006c\" + \"\\u0061\\u0074e\", \"\\u0066\\u0061\\u0063ade\", \"\\u0063\\u006f\" + \"mple" ascii
    $s4 = "while (primitiveTandem[(\"t\" + \"ech\" + \"n\\u0069\\u0071u\\u0065\", \"\\u0074\\u0065l\" + \"e\\u0076i\" + \"\\u0073\" + \"\\u" ascii
    $s5 = "} catch (tropicalUnique) {};" fullword ascii
    $s6 = "provocationCaptain = (((4 ^ 12), (0 ^ 1)), this);" fullword ascii

  condition:
    uint16(0) == 0x7270 and
    all of them
}