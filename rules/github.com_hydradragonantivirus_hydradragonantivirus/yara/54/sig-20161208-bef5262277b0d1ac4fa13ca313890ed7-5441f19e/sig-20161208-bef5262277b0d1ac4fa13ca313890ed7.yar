rule sig_20161208_bef5262277b0d1ac4fa13ca313890ed7 {
  meta:
    description = "datamaliciousorder - file 20161208_bef5262277b0d1ac4fa13ca313890ed7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b88dc40420c96bb2c1394f668fbe28b6a564cb6890dc768c1e3180ff0134c34"

  strings:
    $s1 = " new Date();vYh6[\"setUTC\"+\"FullYear\"](\"2003\");if (vYh6.getUTCFullYear().toString(10) == \"2003\") {var vUe4 = vEq8.split(" ascii
    $s2 = "var vQXj4 = new Function(\"vEq8\", '{return vEq8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vEIx0 = new Function(\"vEq8" ascii
    $s3 = "return vUe4.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vQXj4 = new Function(\"vEq8\", '{return vEq8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vEIx0 = new Function(\"vEq8" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}