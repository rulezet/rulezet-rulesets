rule sig_20160301_b53883dc65a4e07719fecb1c9064cacb {
  meta:
    description = "datamaliciousorder - file 20160301_b53883dc65a4e07719fecb1c9064cacb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "09a360bc788eb4a556fe0dce339d4dd52680c4c279756a3d461b4f03a8b5aa22"

  strings:
    $s1 = "normProgress = synonymStudent[(\"ExpandEnvironmentStrings\")]((\"barrack\", \"%TEMP%/\")) + (\"serious\", \"presumption\", \"hum" ascii
    $s2 = "normProgress = synonymStudent[(\"ExpandEnvironmentStrings\")]((\"barrack\", \"%TEMP%/\")) + (\"serious\", \"presumption\", \"hum" ascii
    $s3 = "tariffBureau = ((Math.pow((116 * 3 + 74), (0 ^ 2)) - (22368 ^ 188883)), this);" fullword ascii
    $s4 = "while (universityResult[(\"suffix\", \"readystate\")] < ((48 / 24) * (([!+[] + !+[]])))) {" fullword ascii
    $s5 = "universityResult = tariffBureau[(\"WScript\")][(\"serial\", function String.prototype.orientationContrast() {" fullword ascii
    $s6 = "} catch (republicRecord) {};" fullword ascii

  condition:
    uint16(0) == 0x6174 and
    all of them
}