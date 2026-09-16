rule sig_20161208_daac8470aa381d185e3c9bf2453e74f9 {
  meta:
    description = "datamaliciousorder - file 20161208_daac8470aa381d185e3c9bf2453e74f9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "18f07c236285ae9b55ed25697721485a224e11b672299ad0dc6e606e669f27ca"

  strings:
    $s1 = " new Date();vRd9[\"setUTC\"+\"FullYear\"](\"2003\");if (vRd9.getUTCFullYear().toString(10) == \"2003\") {var vTVx8 = vAo7.split(" ascii
    $s2 = "var vZDm7 = new Function(\"vAo7\", '{return vAo7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vXXh5 = new Function(\"vAo7" ascii
    $s3 = "var vZDm7 = new Function(\"vAo7\", '{return vAo7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vXXh5 = new Function(\"vAo7" ascii
    $s4 = " return vTVx8.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}