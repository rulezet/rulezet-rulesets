rule sig_20160301_b0d7f6b96a69b799b2404a7a1159e45c {
  meta:
    description = "datamaliciousorder - file 20160301_b0d7f6b96a69b799b2404a7a1159e45c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3742b7a3fa75a4772a986843d8abad886d4a8b570d56fe164b38e56c34d6da94"

  strings:
    $s1 = "tractPrologue = ((48 - 47), this);" fullword ascii
    $s2 = "amortizationRadiation = tractPrologue[(\"\\u0073ym\\u0062\" + \"ol\", \"cu\" + \"r\\u0073i\\u0076e\", \"extra\\u0063\" + \"t\", " ascii
    $s3 = "amortizationRadiation = tractPrologue[(\"\\u0073ym\\u0062\" + \"ol\", \"cu\" + \"r\\u0073i\\u0076e\", \"extra\\u0063\" + \"t\", " ascii
    $s4 = "while (numerationCitation[(\"\\u0074a\\u0063t\" + \"i\\u0063\\u0073\", \"rea\" + \"dy\\u0073\" + \"t\\u0061\\u0074\\u0065\")] < " ascii
    $s5 = "while (numerationCitation[(\"\\u0074a\\u0063t\" + \"i\\u0063\\u0073\", \"rea\" + \"dy\\u0073\" + \"t\\u0061\\u0074\\u0065\")] < " ascii
    $s6 = "} catch (consultantManifesto) {};" fullword ascii

  condition:
    uint16(0) == 0x7274 and
    all of them
}