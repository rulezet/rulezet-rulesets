rule sig_20160301_7154412cdc5731132d2fcbf4e84560ba {
  meta:
    description = "datamaliciousorder - file 20160301_7154412cdc5731132d2fcbf4e84560ba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d332097f10d945c16e6b0f917e5bd47601945aa4d1771a172d4aa5c9d62c46a0"

  strings:
    $s1 = "chanceSolid = ((0 | 3) * (1 | 13) * (3) * (([!+[] + !+[]])), this);" fullword ascii
    $s2 = "while(reanimationLicence[(\"ne\\u0067ative\", \"\\u006f\\u0072\\u0067aniz\\u0061\\u0074\\u0069o\\u006e\", \"\\u0074\\u0072o\\u00" ascii
    $s3 = "tractFormula[(\"acti\\u0076e\", function String.prototype.interpretFact() {" fullword ascii
    $s4 = "while(reanimationLicence[(\"ne\\u0067ative\", \"\\u006f\\u0072\\u0067aniz\\u0061\\u0074\\u0069o\\u006e\", \"\\u0074\\u0072o\\u00" ascii
    $s5 = "} catch(cocoonDocument) {};" fullword ascii

  condition:
    uint16(0) == 0x6863 and
    all of them
}