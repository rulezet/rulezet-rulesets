rule sig_20160301_eccdf0e78950b7b3ebe66e0ba986114f {
  meta:
    description = "datamaliciousorder - file 20160301_eccdf0e78950b7b3ebe66e0ba986114f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0034cc307e5f44bcb50b4f26380e113b529b9a459cec9819bab30dbfe1a3c5f"

  strings:
    $x1 = "commandShorts = reflectionHomogeneous[(\"mechanic\", \"occasion\", \"boss\", \"flag\", \"ExpandEnvironmentStrings\")]((\"person" ascii
    $x2 = "\"dialogue\", \"%TEMP%/\")) + (\"recommend\", \"energy\", \"dogBillion\") + (\"anarchy\", \"amphibian\", \"symbol\", \".scr\");" fullword ascii
    $s3 = "while (forceDelegate[(\"morphology\", \"attribute\", \"effective\", \"readystate\")] < ((0 | 0) ^ (5 & 6))) {" fullword ascii
    $s4 = "} catch (protocolManuscript) {};" fullword ascii
    $s5 = "batteryHandicap = (((45 * 5 + 10) + 2 * 2 * 2 * 2 * 3), this);" fullword ascii
    $s6 = "radiationAbsurd = (\"tract\", function String.prototype.projectAspect() {" fullword ascii

  condition:
    uint16(0) == 0x6162 and
    1 of ($x*) and all of them
}