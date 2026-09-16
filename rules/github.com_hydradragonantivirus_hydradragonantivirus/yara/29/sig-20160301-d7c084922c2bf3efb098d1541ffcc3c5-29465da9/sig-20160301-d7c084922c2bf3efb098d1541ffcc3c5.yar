rule sig_20160301_d7c084922c2bf3efb098d1541ffcc3c5 {
  meta:
    description = "datamaliciousorder - file 20160301_d7c084922c2bf3efb098d1541ffcc3c5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "22aba286b555643ff4616001e576847b1eb7a57f99e7e9ed2486886f4ee4a1ec"

  strings:
    $s1 = "while (statuetteSyntax[(\"boxi\" + \"\\u006e\\u0067\", \"la\\u0062o\\u0072\" + \"at\\u006f\" + \"ry\", \"\\u0065n\" + \"e\" + \"" ascii
    $s2 = "while (statuetteSyntax[(\"boxi\" + \"\\u006e\\u0067\", \"la\\u0062o\\u0072\" + \"at\\u006f\" + \"ry\", \"\\u0065n\" + \"e\" + \"" ascii
    $s3 = "resultNet = (((1) * (0 ^ 1)), this);" fullword ascii
    $s4 = "rhombusCampaign[(\"m\\u0069n\\u0075\" + \"s\", \"\\u0069ndu\\u0073t\" + \"\\u0072\\u0079\", \"s\\u0074\" + \"a\\u006ed\", functi" ascii
    $s5 = "rhombusCampaign[(\"m\\u0069n\\u0075\" + \"s\", \"\\u0069ndu\\u0073t\" + \"\\u0072\\u0079\", \"s\\u0074\" + \"a\\u006ed\", functi" ascii
    $s6 = "} catch (synthesisTelephone) {};" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    all of them
}