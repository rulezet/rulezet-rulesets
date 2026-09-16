rule sig_20161207_8989c8c8264acbd471881545b61bbe96 {
  meta:
    description = "datamaliciousorder - file 20161207_8989c8c8264acbd471881545b61bbe96.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7ebcbf1e4f641d39f83ab9739a59269ecbb5c172953216f5d64828397aa76be0"

  strings:
    $s1 = "var vOZz1 = new Function(\"vZg0\", '{var vZJw3 = new Date();vZJw3[\"setUTCFullYear\"](\"2003\");if (vZJw3.getUTCFullYear().toStr" ascii
    $s2 = "var vOZz1 = new Function(\"vZg0\", '{var vZJw3 = new Date();vZJw3[\"setUTCFullYear\"](\"2003\");if (vZJw3.getUTCFullYear().toStr" ascii
    $s3 = ") == \"2003\") {var vYz0 = vZg0.split(\"###\"); return vYz0.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vJe5 = new Function(\"vZg0\", '{return vZg0.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}