rule sig_20160301_2c4b13c4ce5ac9d31d7e62223bab35d9 {
  meta:
    description = "datamaliciousorder - file 20160301_2c4b13c4ce5ac9d31d7e62223bab35d9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da42c1cd24f9cf9082f08087e797deea6cab07e2d99d99903e13f9e7c810daba"

  strings:
    $s1 = "while (natureCipher[(\"m\\u0065\\u0072\\u0069\\u0064\" + \"ian\", \"amp\" + \"\\u0075\\u0074\\u0061te\", \"\\u0072\\u0065\\u0061" ascii
    $s2 = "while (natureCipher[(\"m\\u0065\\u0072\\u0069\\u0064\" + \"ian\", \"amp\" + \"\\u0075\\u0074\\u0061te\", \"\\u0072\\u0065\\u0061" ascii
    $s3 = "natureCipher = assemblyIndustrialization[(\"\\u0061\\u0063\" + \"\\u0063\\u006f\\u006d\" + \"moda\" + \"\\u0074ion\", function S" ascii
    $s4 = "assemblyIndustrialization = (((14 + 56), (114 ^ 232), (100 + 45), 1), this);" fullword ascii
    $s5 = "natureCipher = assemblyIndustrialization[(\"\\u0061\\u0063\" + \"\\u0063\\u006f\\u006d\" + \"moda\" + \"\\u0074ion\", function S" ascii
    $s6 = "} catch (detailMeditate) {};" fullword ascii

  condition:
    uint16(0) == 0x7361 and
    all of them
}