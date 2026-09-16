rule sig_20161207_0be4c07ef59ab12788cacf1b44f12a84 {
  meta:
    description = "datamaliciousorder - file 20161207_0be4c07ef59ab12788cacf1b44f12a84.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cbd275492cf79f146cdcef1c2e226cd354847866a85cd44f520fd1facb7c7d16"

  strings:
    $s1 = "var vWu9 = new Function(\"vHJw8\", '{var vLHq9 = new Date();vLHq9[\"setUTCFullYear\"](\"2003\");if (vLHq9.getUTCFullYear().toStr" ascii
    $s2 = "var vWu9 = new Function(\"vHJw8\", '{var vLHq9 = new Date();vLHq9[\"setUTCFullYear\"](\"2003\");if (vLHq9.getUTCFullYear().toStr" ascii
    $s3 = ") == \"2003\") {var vMh0 = vHJw8.split(\"###\"); return vMh0.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vSJf8 = new Function(\"vHJw8\", '{return vHJw8.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}