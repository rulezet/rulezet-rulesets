rule sig_20160301_a34ba193786ea0a40e4352d70f572bed {
  meta:
    description = "datamaliciousorder - file 20160301_a34ba193786ea0a40e4352d70f572bed.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6ef17befbab0e860ebde7738250592661c5322838d5598e7199079e5f96994d"

  strings:
    $s1 = "while (practiceRegulate[(\"\\u0061cc\" + \"\\u006f\" + \"mpan\\u0079\", \"r\\u0065\" + \"a\\u0064\\u0079s\" + \"ta\" + \"te\")] " ascii
    $s2 = "while (practiceRegulate[(\"\\u0061cc\" + \"\\u006f\" + \"mpan\\u0079\", \"r\\u0065\" + \"a\\u0064\\u0079s\" + \"ta\" + \"te\")] " ascii
    $s3 = "raidAxiom = (((229, 1) + (22, 0)), this);" fullword ascii
    $s4 = "\"\\u0061\" + \"stro\\u006e\" + \"\\u0061ut\", function String.prototype.decorationBandage() {" fullword ascii
    $s5 = "accumulatorStandard = provisionModal[(\"\\u0061p\" + \"\\u0070a\" + \"\\u0072\" + \"atu\" + \"s\", \"\\u0072esi\\u0073\" + \"\\u" ascii
    $s6 = "} catch (translationPresident) {};" fullword ascii

  condition:
    uint16(0) == 0x6172 and
    all of them
}