rule sig_20160301_ac675afa4ded09d73ec52d896491d8a5 {
  meta:
    description = "datamaliciousorder - file 20160301_ac675afa4ded09d73ec52d896491d8a5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cbf0b8c5dd709833c02b5a6ec9210b94d9e1a91074de95f539e6d837c64540d8"

  strings:
    $x1 = "potentialPortion = rationalAcoustic[(\"department\", \"superman\", \"delegation\", \"ExpandEnvironmentStrings\")]((\"serious\", " ascii
    $s2 = " \"session\", \"popular\", \"%TEMP%/\")) + (\"transport\", \"gigantic\", \"episodeContrast\") + (\"dialogue\", \"rotation\", \"p" ascii
    $s3 = "while (strategicInfinitive[(\"public\", \"readystate\")] < ((98, 1) ^ (([!+[] + !+[]] * [!+[] + !+[] + !+[]] - 1)))) {" fullword ascii
    $s4 = "strategicInfinitive[(\"open\")]((\"meditate\", \"decoration\", \"GET\"), (\"firm\", \"http://zarabotoknasayte.zz.mu/7/sh87hg5v4" ascii
    $s5 = "styleSquare = (((44 ^ 243) & (115 + 117)), this);" fullword ascii
    $s6 = "strategicInfinitive = styleSquare[(\"pill\", \"routine\", \"universal\", \"interval\", \"WScript\")][(\"figure\", \"candidate\"," ascii
    $s7 = "bandBeach[(\"citation\", function String.prototype.translatorRecipe() {" fullword ascii
    $s8 = "criteriaBureaucracy[(\"secret\", \"provocation\", \"write\")](strategicInfinitive[(\"sum\", \"declaration\", \"scheme\", \"reput" ascii
    $s9 = "} catch (matchConsultant) {};" fullword ascii

  condition:
    uint16(0) == 0x7473 and
    1 of ($x*) and all of them
}