rule sig_20160301_f7f1fb7d57488e8b88303bb9e2dd2c76 {
  meta:
    description = "datamaliciousorder - file 20160301_f7f1fb7d57488e8b88303bb9e2dd2c76.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f788557c9d90d7b26dc09765f10d29bb728e52549ac47ffc5b1f0618ddf0afd3"

  strings:
    $x1 = "vibrationExamination = actMagazine[(\"ExpandEnvironmentStrings\")]((\"organ\", \"echo\", \"%TEMP%/\")) + (\"substance\", \"minor" ascii
    $s2 = "vibrationExamination = actMagazine[(\"ExpandEnvironmentStrings\")]((\"organ\", \"echo\", \"%TEMP%/\")) + (\"substance\", \"minor" ascii
    $s3 = "gramEquivalent = ((([!+[] + !+[]]) * ([!+[] + !+[]]) * ([!+[] + !+[] + !+[]]) * ([!+[] + !+[]]) * (((([+!+[]])) + \"\" + (([+!+[" ascii
    $s4 = "while (internationalTypical[(\"readystate\")] < ((1 * 3) ^ (([!+[] + !+[]] * [!+[] + !+[] + !+[]] + 1)))) {" fullword ascii
    $s5 = "guardTariff[(\"record\", function String.prototype.immuneBand() {" fullword ascii
    $s6 = "))))), this);" fullword ascii
    $s7 = "} catch (boomFocus) {};" fullword ascii

  condition:
    uint16(0) == 0x7267 and
    1 of ($x*) and all of them
}