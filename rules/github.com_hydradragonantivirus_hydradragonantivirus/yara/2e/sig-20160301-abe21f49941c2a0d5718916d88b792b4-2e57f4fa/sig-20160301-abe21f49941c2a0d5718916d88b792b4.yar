rule sig_20160301_abe21f49941c2a0d5718916d88b792b4 {
  meta:
    description = "datamaliciousorder - file 20160301_abe21f49941c2a0d5718916d88b792b4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa7e6cdf53167792f394b9dc5a91d2680f0a9164f3c76124b4c2692c4b3fd3e2"

  strings:
    $x1 = "acrobatTactics = brokerObligation[(\"industrial\", \"postscript\", \"ExpandEnvironmentStrings\")]((\"component\", \"%TEMP%/\")) " ascii
    $s2 = "acrobatTactics = brokerObligation[(\"industrial\", \"postscript\", \"ExpandEnvironmentStrings\")]((\"component\", \"%TEMP%/\")) " ascii
    $s3 = "while (genealogyAgent[(\"readystate\")] < ((0 / 46) | (Math.pow(16, 2) - 252))) {" fullword ascii
    $s4 = "paragraphSegment[(\"photograph\", \"infection\", \"dust\", \"write\")](genealogyAgent[(\"sanction\", \"tax\", \"boat\", function" ascii
    $s5 = "paragraphSegment[(\"photograph\", \"infection\", \"dust\", \"write\")](genealogyAgent[(\"sanction\", \"tax\", \"boat\", function" ascii
    $s6 = "transplantFactor = (((6760 - 1743) / (25 | 29)), this);" fullword ascii
    $s7 = "} catch (aspectSeparation) {};" fullword ascii

  condition:
    uint16(0) == 0x7274 and
    1 of ($x*) and all of them
}