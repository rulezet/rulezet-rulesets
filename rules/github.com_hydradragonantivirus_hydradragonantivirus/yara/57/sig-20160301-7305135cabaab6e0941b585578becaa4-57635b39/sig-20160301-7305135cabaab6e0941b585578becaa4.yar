rule sig_20160301_7305135cabaab6e0941b585578becaa4 {
  meta:
    description = "datamaliciousorder - file 20160301_7305135cabaab6e0941b585578becaa4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b4460e14275567f5f2dfb69ca9eb4109035b8c877f4a9659939a6b644eb669cc"

  strings:
    $s1 = "cocoonDate = addressDeclaration[(\"false\", \"dictate\", \"ExpandEnvironmentStrings\")]((\"bank\", \"service\", \"%TEMP%/\")) + " ascii
    $s2 = "cocoonDate = addressDeclaration[(\"false\", \"dictate\", \"ExpandEnvironmentStrings\")]((\"bank\", \"service\", \"%TEMP%/\")) + " ascii
    $s3 = "while(regentCollective[(\"bank\", \"resource\", \"bomber\", \"readystate\")] < ((0 | 33) - (16 ^ 13))) {" fullword ascii
    $s4 = "conditionArctic = (((223, 7) + (2 * 8)), this);" fullword ascii
    $s5 = "regentCollective = conditionArctic[(\"park\", \"symmetrical\", function String.prototype.standNature() {" fullword ascii
    $s6 = "} catch(informEvolution) {};" fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    all of them
}