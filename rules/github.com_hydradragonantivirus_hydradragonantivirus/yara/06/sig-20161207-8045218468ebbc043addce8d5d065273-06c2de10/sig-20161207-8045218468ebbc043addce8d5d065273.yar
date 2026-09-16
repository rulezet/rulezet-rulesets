rule sig_20161207_8045218468ebbc043addce8d5d065273 {
  meta:
    description = "datamaliciousorder - file 20161207_8045218468ebbc043addce8d5d065273.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f14ddd63050baef4358bc5ab8441861ffde9023e5d1fca01ba27c616615aab20"

  strings:
    $s1 = "var vFPw6 = new Function(\"vJKw7\", '{var vDu5 = new Date();vDu5[\"setUTCFullYear\"](\"2003\");if (vDu5.getUTCFullYear().toStrin" ascii
    $s2 = "var vFPw6 = new Function(\"vJKw7\", '{var vDu5 = new Date();vDu5[\"setUTCFullYear\"](\"2003\");if (vDu5.getUTCFullYear().toStrin" ascii
    $s3 = "== \"2003\") {var vWEp1 = vJKw7.split(\"###\"); return vWEp1.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vMl4 = new Function(\"vJKw7\", '{return vJKw7.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}