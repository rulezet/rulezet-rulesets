rule sig_20160301_f2470c85c1ca6b6f129fd076367d2622 {
  meta:
    description = "datamaliciousorder - file 20160301_f2470c85c1ca6b6f129fd076367d2622.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e64b5944f2c1945b80932f6197a9dc792877605e983e0a21a2f1e954c95de14e"

  strings:
    $s1 = "stimulusVacant = clipSubjective[(\"operator\", \"ExpandEnvironmentStrings\")]((\"barge\", \"pulse\", \"%TEMP%/\")) + (\"abstract" ascii
    $s2 = "stimulusVacant = clipSubjective[(\"operator\", \"ExpandEnvironmentStrings\")]((\"barge\", \"pulse\", \"%TEMP%/\")) + (\"abstract" ascii
    $s3 = "importAquarium = (((17 | 17), (104 * 2 + 6), (45 ^ 111)), this);" fullword ascii
    $s4 = "while (subjectiveCollective[(\"company\", \"readystate\")] < ((4 | 0) & (3 | 5))) {" fullword ascii
    $s5 = "} catch (anatomyHobby) {};" fullword ascii

  condition:
    uint16(0) == 0x6d69 and
    all of them
}