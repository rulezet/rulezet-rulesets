rule sig_20161207_a8d823229acced117ce96fa5ae0b2ce8 {
  meta:
    description = "datamaliciousorder - file 20161207_a8d823229acced117ce96fa5ae0b2ce8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b0cbd3138b86a2d6bcbaee8ca768903bf2c046bd309b2ad3df1af9c47fc219c1"

  strings:
    $s1 = "var vLh0 = new Function(\"vMy7\", '{return vMy7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vKu2 = new Function(\"vMy7\"" ascii
    $s2 = "ew Date();vVx1[\"setUTCFullYear\"](\"2003\");if (vVx1.getUTCFullYear().toString(10) == \"2003\") {var vZo9 = vMy7.split(\"####\"" ascii
    $s3 = "var vLh0 = new Function(\"vMy7\", '{return vMy7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vKu2 = new Function(\"vMy7\"" ascii
    $s4 = "n vZo9.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}