rule sig_20161207_c513fcb3da30a0bd02be570b78a4798a {
  meta:
    description = "datamaliciousorder - file 20161207_c513fcb3da30a0bd02be570b78a4798a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "012ab2901ff3e521dd7d1fba58d41d73d127df492eca1a149544f446b25b6f7c"

  strings:
    $s1 = "var vWFh3 = new Function(\"vAf0\", '{var vOs4 = new Date();vOs4[\"setUTCFullYear\"](\"2003\");if (vOs4.getUTCFullYear().toString" ascii
    $s2 = "var vWFh3 = new Function(\"vAf0\", '{var vOs4 = new Date();vOs4[\"setUTCFullYear\"](\"2003\");if (vOs4.getUTCFullYear().toString" ascii
    $s3 = "var vAOs5 = new Function(\"vAf0\", '{return vAf0.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "= \"2003\") {var vYo9 = vAf0.split(\"###\"); return vYo9.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}