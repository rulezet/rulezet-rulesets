rule sig_20161207_2400626586423387ae33e9a575330752 {
  meta:
    description = "datamaliciousorder - file 20161207_2400626586423387ae33e9a575330752.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "52af1787dbbd18ffc80a505b2cbcd8f860481dee99e9a5f3c5a1c92648520b4a"

  strings:
    $s1 = "var vVPy0 = new Function(\"vMy7\", '{var vZVq6 = new Date();vZVq6[\"setUTCFullYear\"](\"2003\");if (vZVq6.getUTCFullYear().toStr" ascii
    $s2 = "var vVPy0 = new Function(\"vMy7\", '{var vZVq6 = new Date();vZVq6[\"setUTCFullYear\"](\"2003\");if (vZVq6.getUTCFullYear().toStr" ascii
    $s3 = ") == \"2003\") {var vKBc9 = vMy7.split(\"###\"); return vKBc9.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vENw5 = new Function(\"vMy7\", '{return vMy7.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}