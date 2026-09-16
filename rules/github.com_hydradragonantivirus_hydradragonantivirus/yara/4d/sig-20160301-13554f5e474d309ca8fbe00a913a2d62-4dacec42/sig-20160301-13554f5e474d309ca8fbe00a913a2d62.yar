rule sig_20160301_13554f5e474d309ca8fbe00a913a2d62 {
  meta:
    description = "datamaliciousorder - file 20160301_13554f5e474d309ca8fbe00a913a2d62.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e7aad502135a6e62bae72f65929da61b082ee9bc827fd55a0282e1bd68fde0d"

  strings:
    $s1  = "} catch (processComment) {};" fullword ascii
    $s2  = "while (microphoneConfiguration[(\"ro\\u0063k\" + \"\\u0065t\", \"r\\u0065\\u0061\" + \"dy\\u0073t\\u0061t\" + \"\\u0065\")] < ((" ascii
    $s3  = "while (microphoneConfiguration[(\"ro\\u0063k\" + \"\\u0065t\", \"r\\u0065\\u0061\" + \"dy\\u0073t\\u0061t\" + \"\\u0065\")] < ((" ascii
    $s4  = "  accentInterpretation[(\"\\u0076\" + \"i\" + \"sa\", \"p\\u0072i\" + \"\\u006e\\u0063e\", \"g\\u0065n\\u0065\" + \"r\\u0061\" +" ascii
    $s5  = "accentInterpretation = (((0 / 1) + (1 * 1)), this);" fullword ascii
    $s6  = "  accentInterpretation[(\"\\u0076\" + \"i\" + \"sa\", \"p\\u0072i\" + \"\\u006e\\u0063e\", \"g\\u0065n\\u0065\" + \"r\\u0061\" +" ascii
    $s7  = "radioLocation = beastZombie[(\"\\u0076a\\u0063uu\" + \"\\u006d\", \"in\\u0076\" + \"er\\u0073\\u0069\" + \"\\u006fn\", \"\\u0070" ascii
    $s8  = "radioLocation = beastZombie[(\"\\u0076a\\u0063uu\" + \"\\u006d\", \"in\\u0076\" + \"er\\u0073\\u0069\" + \"\\u006fn\", \"\\u0070" ascii
    $s9  = "tonicMonster = radioLocation[(\"pa\" + \"s\\u0073\\u0069\\u006f\" + \"n\", \"the\\u006f\" + \"rem\", \"\\u0061uc\\u0074\" + \"" ascii
    $s10 = "tonicMonster = radioLocation[(\"pa\" + \"s\\u0073\\u0069\\u006f\" + \"n\", \"the\\u006f\" + \"rem\", \"\\u0061uc\\u0074\" + \"" ascii
    $s11 = "  radioLocation[massDemon](tonicMonster.publicInfinitive(), (0 ^ (0 / 48)), (([+[]])));" fullword ascii

  condition:
    uint16(0) == 0x6361 and
    8 of them
}