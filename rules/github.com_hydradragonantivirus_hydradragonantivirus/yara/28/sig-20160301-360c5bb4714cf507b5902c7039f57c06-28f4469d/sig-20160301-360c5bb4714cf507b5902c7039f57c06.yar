rule sig_20160301_360c5bb4714cf507b5902c7039f57c06 {
  meta:
    description = "datamaliciousorder - file 20160301_360c5bb4714cf507b5902c7039f57c06.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "80cb789c488ac3adb3460ea5e59ba8c05ee6f3b97da14f3df657e2211cfb5ad7"

  strings:
    $s1 = "standardEffect = censorEmblem[(\"ExpandEnvironmentStrings\")]((\"formation\", \"scalpel\", \"%TEMP%/\")) + (\"generation\", \"co" ascii
    $s2 = "standardEffect = censorEmblem[(\"ExpandEnvironmentStrings\")]((\"formation\", \"scalpel\", \"%TEMP%/\")) + (\"generation\", \"co" ascii
    $s3 = "operatorAmmunition = (((11 + 18) ^ (([!+[] + !+[] + !+[]]) * ([!+[] + !+[]] * [!+[] + !+[] + !+[]] - 1) * ([!+[] + !+[] + !+[]])" ascii
    $s4 = "energyUniversity = operatorAmmunition[(\"initiative\", \"sphere\", \"WScript\")][(\"dust\", \"instance\", \"pause\", function St" ascii
    $s5 = "energyUniversity = operatorAmmunition[(\"initiative\", \"sphere\", \"WScript\")][(\"dust\", \"instance\", \"pause\", function St" ascii
    $s6 = "while (energyUniversity[(\"readystate\")] < ((1 * 3) ^ (7 + 0))) {" fullword ascii
    $s7 = "} catch (complexSwitch) {};" fullword ascii
    $s8 = ")), this);" fullword ascii

  condition:
    uint16(0) == 0x706f and
    all of them
}