rule sig_20161207_96bde54031869eaef667d91a5a667c6a {
  meta:
    description = "datamaliciousorder - file 20161207_96bde54031869eaef667d91a5a667c6a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b6849c6dd275d31375c7e560e0921be6e057d8c41b490e3aae31ee1b63b98ba3"

  strings:
    $s1 = "var vUXm9 = new Function(\"vDEe8\", '{var vWw7 = new Date();vWw7[\"setUTCFullYear\"](\"2003\");if (vWw7.getUTCFullYear().toStrin" ascii
    $s2 = "var vUXm9 = new Function(\"vDEe8\", '{var vWw7 = new Date();vWw7[\"setUTCFullYear\"](\"2003\");if (vWw7.getUTCFullYear().toStrin" ascii
    $s3 = "var vROb9 = new Function(\"vDEe8\", '{return vDEe8.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "== \"2003\") {var vFXj0 = vDEe8.split(\"###\"); return vFXj0.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}