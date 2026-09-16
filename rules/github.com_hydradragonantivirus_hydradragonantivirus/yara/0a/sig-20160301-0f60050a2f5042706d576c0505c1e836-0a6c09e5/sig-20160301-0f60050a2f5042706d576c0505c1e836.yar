rule sig_20160301_0f60050a2f5042706d576c0505c1e836 {
  meta:
    description = "datamaliciousorder - file 20160301_0f60050a2f5042706d576c0505c1e836.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "644521c98038576c7e9eac68e1702b21311337ff5f6b0f3103bf6c140cbf1fdb"

  strings:
    $s1 = "portClass = pressTonic[(\"stand\", \"ExpandEnvironmentStrings\")]((\"statuette\", \"collision\", \"%TEMP%/\")) + (\"modifyReflex" ascii
    $s2 = "portClass = pressTonic[(\"stand\", \"ExpandEnvironmentStrings\")]((\"statuette\", \"collision\", \"%TEMP%/\")) + (\"modifyReflex" ascii
    $s3 = "while(telephoneDuplicate[(\"cortege\", \"airplane\", \"readystate\")] < ((Math.pow(9, 2) - 77) | (([+[]])))) {" fullword ascii
    $s4 = "distantMilitary = (((((([!+[] + !+[]])) + \"\" + (([!+[] + !+[]])) + \"\" + (([!+[] + !+[]] * [!+[] + !+[] + !+[]] + (6 / 6)))))" ascii
    $s5 = "contractVertical = distantMilitary[(\"plan\", function String.prototype.duplicatePulse() {" fullword ascii
    $s6 = "} catch(illustrateConfidential) {};" fullword ascii

  condition:
    uint16(0) == 0x6964 and
    all of them
}