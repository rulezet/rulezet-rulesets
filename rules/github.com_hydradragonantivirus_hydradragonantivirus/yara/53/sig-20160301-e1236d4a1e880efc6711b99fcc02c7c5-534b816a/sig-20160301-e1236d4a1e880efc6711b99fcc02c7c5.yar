rule sig_20160301_e1236d4a1e880efc6711b99fcc02c7c5 {
  meta:
    description = "datamaliciousorder - file 20160301_e1236d4a1e880efc6711b99fcc02c7c5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4a48129cc0aa15be9720e8a4b635eccfd16417a755608c768dc74bca14fcb2be"

  strings:
    $s1 = "stopChaos = conditionRisk[(\"motivate\", \"intellect\", \"routine\", \"private\", \"ExpandEnvironmentStrings\")]((\"%TEMP%/\")) " ascii
    $s2 = "stopChaos = conditionRisk[(\"motivate\", \"intellect\", \"routine\", \"private\", \"ExpandEnvironmentStrings\")]((\"%TEMP%/\")) " ascii
    $s3 = "while(circleMarch[(\"readystate\")] < (2 & 2) * (2 & 3)) {" fullword ascii
    $s4 = "linguistComfort[(\"appeal\", \"anatomy\", \"WScript\")][(\"prize\", \"export\", \"transmission\", function String.prototype.acad" ascii
    $s5 = "linguistComfort[(\"appeal\", \"anatomy\", \"WScript\")][(\"prize\", \"export\", \"transmission\", function String.prototype.acad" ascii
    $s6 = "linguistComfort = ((167 & 179), this);" fullword ascii
    $s7 = "} catch(antennaTone) {};" fullword ascii

  condition:
    uint16(0) == 0x696c and
    all of them
}