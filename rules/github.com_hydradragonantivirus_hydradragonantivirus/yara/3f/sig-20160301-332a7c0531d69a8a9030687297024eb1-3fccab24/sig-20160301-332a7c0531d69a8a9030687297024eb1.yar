rule sig_20160301_332a7c0531d69a8a9030687297024eb1 {
  meta:
    description = "datamaliciousorder - file 20160301_332a7c0531d69a8a9030687297024eb1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b06ac35c12b4e330fb651482e2607c0a2cf54ef5792b9a66ee09d0f812728038"

  strings:
    $s1 = "while (rotationJungle[(\"\\u0072\\u0065\\u0061\" + \"dy\\u0073\\u0074\" + \"a\\u0074e\")] < ((49 - 45) | (250, 4))) {" fullword ascii
    $s2 = "conceptionInformer[(\"\\u0074\\u0072\\u0061n\\u0073\" + \"lati\" + \"\\u006f\\u006e\", \"\\u0063o\\u006cl\" + \"ectiv\" + \"\\u0" ascii
    $s3 = "conceptionInformer[(\"\\u0074\\u0072\\u0061n\\u0073\" + \"lati\" + \"\\u006f\\u006e\", \"\\u0063o\\u006cl\" + \"ectiv\" + \"\\u0" ascii
    $s4 = "listStrategic = (((0 ^ 1) + (([+[]]))), this);" fullword ascii
    $s5 = "} catch (ballastEcho) {};" fullword ascii

  condition:
    uint16(0) == 0x696c and
    all of them
}