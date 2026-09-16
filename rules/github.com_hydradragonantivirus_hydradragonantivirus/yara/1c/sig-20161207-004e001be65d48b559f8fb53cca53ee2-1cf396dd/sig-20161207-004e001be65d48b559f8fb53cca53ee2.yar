rule sig_20161207_004e001be65d48b559f8fb53cca53ee2 {
  meta:
    description = "datamaliciousorder - file 20161207_004e001be65d48b559f8fb53cca53ee2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3716a56f853a7aaf702994ba9fc7348f0445fcec946b0c546f9a44dc8787e80"

  strings:
    $s1 = "var vOZd4 = new Function(\"vIz6\", '{var vODt3 = new Date();vODt3[\"setUTCFullYear\"](\"2003\");if (vODt3.getUTCFullYear().toStr" ascii
    $s2 = "var vOZd4 = new Function(\"vIz6\", '{var vODt3 = new Date();vODt3[\"setUTCFullYear\"](\"2003\");if (vODt3.getUTCFullYear().toStr" ascii
    $s3 = ") == \"2003\") {var vDr0 = vIz6.split(\"###\"); return vDr0.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vXv5 = new Function(\"vIz6\", '{return vIz6.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}