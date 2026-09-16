rule sig_20160301_ef11bd9d78343e39afc806e95aa9580f {
  meta:
    description = "datamaliciousorder - file 20160301_ef11bd9d78343e39afc806e95aa9580f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8cc62c2f3dd270097b5ffd2b7dc97f89f092fc05c4ec30d895637481fdaea153"

  strings:
    $s1 = "}, \"ExpandEnvironmentStrings\")]((\"collective\", \"progression\", \"objective\", \"%TEMP%/\")) + (\"original\", \"episode\", " ascii
    $s2 = "}, \"ExpandEnvironmentStrings\")]((\"collective\", \"progression\", \"objective\", \"%TEMP%/\")) + (\"original\", \"episode\", " ascii
    $s3 = "while (saluteReserve[(\"pill\", \"readystate\")] < ((248 - 127), (29 & 29), (([!+[] + !+[]] * [!+[] + !+[] + !+[]] - 1) * ([!+[]" ascii
    $s4 = "while (saluteReserve[(\"pill\", \"readystate\")] < ((248 - 127), (29 & 29), (([!+[] + !+[]] * [!+[] + !+[] + !+[]] - 1) * ([!+[]" ascii
    $s5 = "fileUnison = terminologyPreamble[(\"director\", function String.prototype.obligationDecoration() {" fullword ascii
    $s6 = "individualityUnison = ((([!+[] + !+[] + !+[]]) * ([!+[] + !+[] + !+[]]) * (((([!+[] + !+[]])) + \"\" + (([!+[] + !+[] + !+[]]) *" ascii
    $s7 = "[!+[] + !+[] + !+[]]))))), this);" fullword ascii
    $s8 = "} catch (opponentChief) {};" fullword ascii

  condition:
    uint16(0) == 0x6e69 and
    all of them
}