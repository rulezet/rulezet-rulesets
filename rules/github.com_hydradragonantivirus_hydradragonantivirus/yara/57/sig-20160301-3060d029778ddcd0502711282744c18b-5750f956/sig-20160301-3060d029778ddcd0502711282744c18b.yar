rule sig_20160301_3060d029778ddcd0502711282744c18b {
  meta:
    description = "datamaliciousorder - file 20160301_3060d029778ddcd0502711282744c18b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "31836b8a41e43b0b08bf8b323c12fa9fcbb2c772a362ac2b2861b75e4f4646f0"

  strings:
    $s1 = "statisticalAccordion = ballastTrophy[(\"record\", \"angel\", \"ExpandEnvironmentStrings\")]((\"double\", \"%TEMP%/\")) + (\"segm" ascii
    $s2 = "statisticalAccordion = ballastTrophy[(\"record\", \"angel\", \"ExpandEnvironmentStrings\")]((\"double\", \"%TEMP%/\")) + (\"segm" ascii
    $s3 = "while(graphicDegradation[(\"economy\", \"autograph\", \"readystate\")] < (([!+[] + !+[]]) * ([!+[] + !+[]]))) {" fullword ascii
    $s4 = "examineStrategic = ((3 + (1 * 0)), this);" fullword ascii
    $s5 = "} catch(generatorAnarchy) {};" fullword ascii
    $s6 = "recordPaste[(\"chocolate\", \"evolution\", \"collect\", \"write\")](graphicDegradation[(\"final\", function String.prototype.can" ascii
    $s7 = "recordPaste[(\"chocolate\", \"evolution\", \"collect\", \"write\")](graphicDegradation[(\"final\", function String.prototype.can" ascii

  condition:
    uint16(0) == 0x7865 and
    all of them
}