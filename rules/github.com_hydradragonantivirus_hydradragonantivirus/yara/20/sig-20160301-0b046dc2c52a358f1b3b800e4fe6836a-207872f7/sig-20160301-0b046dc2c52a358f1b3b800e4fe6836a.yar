rule sig_20160301_0b046dc2c52a358f1b3b800e4fe6836a {
  meta:
    description = "datamaliciousorder - file 20160301_0b046dc2c52a358f1b3b800e4fe6836a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "446dba807a0558967a85beec5e7a020a891a14d0db043bf1e8ac9a2398a4250d"

  strings:
    $s1  = "commissionMotor = certificatePrince[(\"repetition\", \"transmission\", \"ExpandEnvironmentStrings\")]((\"tropical\", \"%TEMP%/\"" ascii
    $s2  = "while (shockIntelligence[(\"phrase\", \"stand\", \"pill\", \"readystate\")] < (Math.pow((Math.pow(3, 2) - 5), (([!+[] + !+[]])))" ascii
    $s3  = "while (shockIntelligence[(\"phrase\", \"stand\", \"pill\", \"readystate\")] < (Math.pow((Math.pow(3, 2) - 5), (([!+[] + !+[]])))" ascii
    $s4  = "commissionMotor = certificatePrince[(\"repetition\", \"transmission\", \"ExpandEnvironmentStrings\")]((\"tropical\", \"%TEMP%/\"" ascii
    $s5  = "contactDepartment = ((([!+[] + !+[]] * [!+[] + !+[] + !+[]] - (([+!+[]]))) * ([!+[] + !+[]] * [!+[] + !+[] + !+[]] - 1) * ([!+[]" ascii
    $s6  = " + !+[]] * [!+[] + !+[] + !+[]] - (0 | 1)) * ([!+[] + !+[]])), this);" fullword ascii
    $s7  = "\", function String.prototype.substanceReform() {" fullword ascii
    $s8  = "certificatePrince = presentProfessional[(\"mate\", \"precedent\", \"precision\", \"CreateObject\")]((\"typical\", \"cylinder\", " ascii
    $s9  = "} catch (relaxationImage) {};" fullword ascii
    $s10 = "certificatePrince = presentProfessional[(\"mate\", \"precedent\", \"precision\", \"CreateObject\")]((\"typical\", \"cylinder\", " ascii

  condition:
    uint16(0) == 0x6f63 and
    all of them
}