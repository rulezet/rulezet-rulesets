rule sig_20160301_8c17a635c2950304cab3cd4382ed951c {
  meta:
    description = "datamaliciousorder - file 20160301_8c17a635c2950304cab3cd4382ed951c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ebd5a5cdc19bc8412083179608d0345c75951a1e11101d7cd90f2acbc0bb4f94"

  strings:
    $s1 = "dessertMaterial = ((([!+[] + !+[]]) * (((([+!+[]])) + \"\" + (([+!+[]])))) * ([!+[] + !+[] + !+[]])), this);" fullword ascii
    $s2 = "while (regularCollective[(\"mer\\u0069d\\u0069\\u0061\\u006e\", \"r\\u0065\\u0061d\\u0079\\u0073\\u0074at\\u0065\")] < ((3 + 4) " ascii
    $s3 = "symmetricalPolar[(\"p\\u006can\", function String.prototype.decorationNumeration() {" fullword ascii
    $s4 = "} catch (pauseClub) {};" fullword ascii

  condition:
    uint16(0) == 0x6564 and
    all of them
}