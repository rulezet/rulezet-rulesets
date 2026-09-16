rule sig_20160301_273ac72649908a3c5d8d7479d270a462 {
  meta:
    description = "datamaliciousorder - file 20160301_273ac72649908a3c5d8d7479d270a462.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "081f46b7120c2412b2186c625a55581868fb02de9c135cddd31aea8a18d692f0"

  strings:
    $s1 = "autographEmotion = automobileJunior[(\"comfort\", \"raid\", \"march\", \"ExpandEnvironmentStrings\")]((\"scalpel\", \"%TEMP%/\")" ascii
    $s2 = "while(intervalCommander[(\"readystate\")] < ((3 * 2) & 5)) {" fullword ascii
    $s3 = "portionMonster = ((Math.pow((Math.pow(85, 2) - 7075), (0 | 2)) - (15224 ^ 28083)), this);" fullword ascii
    $s4 = "autographEmotion = automobileJunior[(\"comfort\", \"raid\", \"march\", \"ExpandEnvironmentStrings\")]((\"scalpel\", \"%TEMP%/\")" ascii
    $s5 = "ruinProblem = portionMonster[(\"lethal\", \"indifferent\", \"arcade\", \"technical\", \"WScript\")][(\"port\", \"director\", \"p" ascii
    $s6 = "} catch(contributionEnergy) {};" fullword ascii

  condition:
    uint16(0) == 0x6f70 and
    all of them
}