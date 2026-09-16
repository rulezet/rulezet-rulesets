rule sig_20160923_a0fcca8db5e9937045cb8bed3b8aa49f {
  meta:
    description = "datamaliciousorder - file 20160923_a0fcca8db5e9937045cb8bed3b8aa49f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "621064dc1afc28197f7f2ae983702422c0fd61e7e0b0d2f1811a5d564652f2f4"

  strings:
    $s1 = "var ynokliz2 = new Array('ha', 'u', 'anc', 'a', 'i', 'fiq', 'ci', 'oq', 'ajo', 'ynz', 'xc', 'iwe', 'hkezc', WScript, 'aro', 'fpu" ascii
    $s2 = "var ynokliz2 = new Array('ha', 'u', 'anc', 'a', 'i', 'fiq', 'ci', 'oq', 'ajo', 'ynz', 'xc', 'iwe', 'hkezc', WScript, 'aro', 'fpu" ascii
    $s3 = "var itqaqe08 = new Function({" fullword ascii
    $s4 = "var mdapbadekzo = new Function({" fullword ascii
    $s5 = "var irhikigs2 = new Function({" fullword ascii
    $s6 = "} catch (nbyvni4) {}" fullword ascii

  condition:
    uint16(0) == 0x7274 and
    all of them
}