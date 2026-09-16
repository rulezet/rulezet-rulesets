rule sig_20160301_88111a53968bbea7cb38d0a688ae006a {
  meta:
    description = "datamaliciousorder - file 20160301_88111a53968bbea7cb38d0a688ae006a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "677918ebcda3bfbdf3d112f8d8b9cde25253343611b4f40322cb34684a896787"

  strings:
    $s1 = "toxicCapitulation = arcadeElement[(\"deposit\", \"ExpandEnvironmentStrings\")]((\"sector\", \"cabinet\", \"business\", \"adaptat" ascii
    $s2 = "while(bomberAviation[(\"bandit\", \"configuration\", \"document\", \"readystate\")] < ((2 * 2) & (Math.pow(20, 2) - 394))) {" fullword ascii
    $s3 = "amperePositive = translationAutomobile[(\"WScript\")][(\"compact\", \"CreateObject\")]((\"balloon\", \"inspector\", \"cardinal\"" ascii
    $s4 = "translationAutomobile = (((31 + 106) | (2967 / 23)), this);" fullword ascii
    $s5 = "function String.prototype.academyRevue() {" fullword ascii
    $s6 = "} catch(minorIndifferent) {};" fullword ascii

  condition:
    uint16(0) == 0x7274 and
    all of them
}