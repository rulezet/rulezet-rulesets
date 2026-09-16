rule sig_20161207_e3cf2719db4ab35539a98e75f19fd0a1 {
  meta:
    description = "datamaliciousorder - file 20161207_e3cf2719db4ab35539a98e75f19fd0a1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "449f53afd793a78a59aebd90caf8100cc6e573e3b2450a025fe5e9efe861b0e5"

  strings:
    $s1 = "var vFPj5 = new Function(\"vYw1\", '{var vGp0 = new Date();vGp0[\"setUTCFullYear\"](\"2003\");if (vGp0.getUTCFullYear().toString" ascii
    $s2 = "var vFPj5 = new Function(\"vYw1\", '{var vGp0 = new Date();vGp0[\"setUTCFullYear\"](\"2003\");if (vGp0.getUTCFullYear().toString" ascii
    $s3 = "var vNLm9 = new Function(\"vYw1\", '{return vYw1.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "= \"2003\") {var vOHc4 = vYw1.split(\"###\"); return vOHc4.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}