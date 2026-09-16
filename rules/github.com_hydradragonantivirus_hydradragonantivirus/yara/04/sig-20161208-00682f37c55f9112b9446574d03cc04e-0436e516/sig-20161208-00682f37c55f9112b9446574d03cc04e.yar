rule sig_20161208_00682f37c55f9112b9446574d03cc04e {
  meta:
    description = "datamaliciousorder - file 20161208_00682f37c55f9112b9446574d03cc04e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b84c68924a44b354f69872c2c15ce55320482e2bf4c446d14a6987f17b7b5560"

  strings:
    $s1 = "var vWp7 = new Function(\"vOz0\", '{return vOz0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vDYx0 = new Function(\"vOz0" ascii
    $s2 = "new Date();vAf1[\"setUTC\"+\"FullYear\"](\"2003\");if (vAf1.getUTCFullYear().toString(10) == \"2003\") {var vNTq5 = vOz0.split(" ascii
    $s3 = "var vWp7 = new Function(\"vOz0\", '{return vOz0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vDYx0 = new Function(\"vOz0" ascii
    $s4 = "return vNTq5.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}