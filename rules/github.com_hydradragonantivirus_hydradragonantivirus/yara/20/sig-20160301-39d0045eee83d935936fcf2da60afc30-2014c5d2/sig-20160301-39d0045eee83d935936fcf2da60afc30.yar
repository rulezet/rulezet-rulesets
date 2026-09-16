rule sig_20160301_39d0045eee83d935936fcf2da60afc30 {
  meta:
    description = "datamaliciousorder - file 20160301_39d0045eee83d935936fcf2da60afc30.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e953c414752f8e84a6408944f8f55a6a1b6b69e7082ae296cb07752e0084e36"

  strings:
    $x1 = "chanceAbsorption = materialDegeneration[(\"lethal\", \"academic\", \"voyage\", \"injection\", \"ExpandEnvironmentStrings\")]((\"" ascii
    $s2 = "\"apostrophe\", \"simulate\", \"%TEMP%/\")) + (\"typical\", \"focus\", \"parole\", \"refrigerator\", \"realStudent\") + (\"colle" ascii
    $s3 = "while (actorBoom[(\"readystate\")] < (2 * 5 * 2 / (([!+[] + !+[]] * [!+[] + !+[] + !+[]] - 1)))) {" fullword ascii
    $s4 = "evolutionFirm = (((150) - (1 * 1)), this);" fullword ascii
    $s5 = "} catch (accentImperative) {};" fullword ascii
    $s6 = "actorBoom[(\"actor\", \"plus\", \"open\")]((\"alphabet\", \"syndicate\", function String.prototype.arcadeProduct() {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    1 of ($x*) and all of them
}