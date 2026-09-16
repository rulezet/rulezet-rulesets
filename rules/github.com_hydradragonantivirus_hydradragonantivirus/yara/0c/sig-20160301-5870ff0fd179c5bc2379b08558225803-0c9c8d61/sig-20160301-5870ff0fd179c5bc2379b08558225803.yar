rule sig_20160301_5870ff0fd179c5bc2379b08558225803 {
  meta:
    description = "datamaliciousorder - file 20160301_5870ff0fd179c5bc2379b08558225803.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b3f54da11e607f81c2b19eea6a581b56f19b8acd8a9dc049fe96f68903607357"

  strings:
    $s1 = "standardMandate = universalSymbol[(\"ExpandEnvironmentStrings\")]((\"%TEMP%/\")) + (\"amorphousClub\") + (\"reservoir\", \"infla" ascii
    $s2 = "standardMandate = universalSymbol[(\"ExpandEnvironmentStrings\")]((\"%TEMP%/\")) + (\"amorphousClub\") + (\"reservoir\", \"infla" ascii
    $s3 = "while (airplaneObligation[(\"symbol\", \"readystate\")] < ((72 + 12) / (2 * 10 + 1))) {" fullword ascii
    $s4 = "ballastAdaptation = (((((([+!+[]])) + \"\" + (([!+[] + !+[]] * [!+[] + !+[] + !+[]] + 1)))) * ([!+[] + !+[]]) * ([!+[] + !+[]]) " ascii
    $s5 = "([!+[] + !+[] + !+[]])), this);" fullword ascii
    $s6 = "airplaneObligation = ballastAdaptation[(\"firm\", \"yacht\", function String.prototype.barrierNavigate() {" fullword ascii
    $s7 = "} catch (bomberArgument) {};" fullword ascii

  condition:
    uint16(0) == 0x6162 and
    all of them
}