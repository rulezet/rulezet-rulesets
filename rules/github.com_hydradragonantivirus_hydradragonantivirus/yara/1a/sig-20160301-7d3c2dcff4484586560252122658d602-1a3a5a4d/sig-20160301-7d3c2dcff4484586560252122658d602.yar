rule sig_20160301_7d3c2dcff4484586560252122658d602 {
  meta:
    description = "datamaliciousorder - file 20160301_7d3c2dcff4484586560252122658d602.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c64e48fc55e5b2351cbda09bbe3fd0b2e53afbd77cc8014fefd0993867f671b5"

  strings:
    $s1 = "while (assistantCorporation[(\"\\u0072e\\u0061\" + \"d\" + \"ys\" + \"\\u0074ate\")] < ((22 - 6) - (97, 243, 12))) {" fullword ascii
    $s2 = "yachtImport = supermanUniform[(\"tic\" + \"k\", \"s\\u0065x\", \"\\u0057S\\u0063\\u0072\\u0069\\u0070\" + \"\\u0074\")][(\"s\" +" ascii
    $s3 = "t\" + \"\\u0075s\", \"\\u0067\" + \"l\\u006fbe\", function String.prototype.liberalStatus() {" fullword ascii
    $s4 = "supermanUniform = ((30 / 30), this);" fullword ascii
    $s5 = "} catch (hierarchyReaction) {};" fullword ascii

  condition:
    uint16(0) == 0x7573 and
    all of them
}