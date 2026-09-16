rule sig_20161207_61e1579602f9a10d0f20b90f5e4dfcce {
  meta:
    description = "datamaliciousorder - file 20161207_61e1579602f9a10d0f20b90f5e4dfcce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1635a5ee229fa6caa73c5445f41ec0cee0e09f8577ddf60f07a471564d1aa704"

  strings:
    $s1 = "var vQp9 = new Function(\"vDVl0\", '{var vEz0 = new Date();vEz0[\"setUTCFullYear\"](\"2003\");if (vEz0.getUTCFullYear().toString" ascii
    $s2 = "var vQp9 = new Function(\"vDVl0\", '{var vEz0 = new Date();vEz0[\"setUTCFullYear\"](\"2003\");if (vEz0.getUTCFullYear().toString" ascii
    $s3 = "var vFm3 = new Function(\"vDVl0\", '{return vDVl0.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "= \"2003\") {var vDg4 = vDVl0.split(\"###\"); return vDg4.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}