rule sig_20161207_1c3abd4b5aa325155e9ebc4192985f9a {
  meta:
    description = "datamaliciousorder - file 20161207_1c3abd4b5aa325155e9ebc4192985f9a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aade072234775895307e01a959ff4a0c88311b0a3baa5a236dd2efab9d8c412e"

  strings:
    $s1 = "var vIFr4 = new Function(\"vPr0\", '{var vVKu2 = new Date();vVKu2[\"setUTCFullYear\"](\"2003\");if (vVKu2.getUTCFullYear().toStr" ascii
    $s2 = "var vIFr4 = new Function(\"vPr0\", '{var vVKu2 = new Date();vVKu2[\"setUTCFullYear\"](\"2003\");if (vVKu2.getUTCFullYear().toStr" ascii
    $s3 = "var vLGs4 = new Function(\"vPr0\", '{return vPr0.split(\",\").join(\"\");};');" fullword ascii
    $s4 = ") == \"2003\") {var vEu1 = vPr0.split(\"###\"); return vEu1.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}