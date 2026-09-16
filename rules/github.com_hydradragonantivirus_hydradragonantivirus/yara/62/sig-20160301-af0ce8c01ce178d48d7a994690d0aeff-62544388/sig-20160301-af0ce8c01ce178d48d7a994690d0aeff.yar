rule sig_20160301_af0ce8c01ce178d48d7a994690d0aeff {
  meta:
    description = "datamaliciousorder - file 20160301_af0ce8c01ce178d48d7a994690d0aeff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28c7e3a6ef0f863d8b20fe8e8a55200ae75141c9ad3d87b247bc023854a57c95"

  strings:
    $s1 = "tre\", \"%TEMP%/\")) + (\"radar\", \"effective\", \"reservation\", \"projection\", \"recommendSaturation\") + (\"registry\", \"a" ascii
    $s2 = "preservativeProduce = operaCondition[(\"effective\", \"WScript\")][(\"monster\", \"spindle\", \"pretension\", \"CreateObject\")]" ascii
    $s3 = "clipRadical = academyVersion[(\"inert\", \"delegate\", \"commission\", \"ExpandEnvironmentStrings\")]((\"delta\", \"phrase\", \"" ascii
    $s4 = "planetFormula = operaCondition[(\"aspect\", \"postscript\", \"contact\", \"WScript\")][(\"vertical\", \"status\", \"report\", \"" ascii
    $s5 = "operaCondition = (((36 * 3 + 8), (5661 / 37), (55 * 2 + 35)), this);" fullword ascii
    $s6 = "while (preservativeProduce[(\"readystate\")] < (([!+[] + !+[]]) * ([!+[] + !+[]]))) {" fullword ascii
    $s7 = "ateObject\")]((\"vacant\", \"artist\", \"analogy\", \"elastic\", function String.prototype.riskThesis() {" fullword ascii
    $s8 = "} catch (blockadeSocial) {};" fullword ascii

  condition:
    uint16(0) == 0x706f and
    all of them
}