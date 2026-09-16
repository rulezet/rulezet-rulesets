rule sig_20161208_346c3694e9f8390e5a331f02458dc371 {
  meta:
    description = "datamaliciousorder - file 20161208_346c3694e9f8390e5a331f02458dc371.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "88bdbf4197dbfab6c2620d15a7e05f76a1d7ccf72225921e66097e535b07258c"

  strings:
    $s1 = "var vTt7 = new Function(\"vQDy2\", '{return vQDy2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vHKy9 = new Function(\"vQD" ascii
    $s2 = "6 = new Date();vUDx6[\"setUTC\"+\"FullYear\"](\"2003\");if (vUDx6.getUTCFullYear().toString(10) == \"2003\") {var vOUj0 = vQDy2." ascii
    $s3 = "###\"); return vOUj0.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vTt7 = new Function(\"vQDy2\", '{return vQDy2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vHKy9 = new Function(\"vQD" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}