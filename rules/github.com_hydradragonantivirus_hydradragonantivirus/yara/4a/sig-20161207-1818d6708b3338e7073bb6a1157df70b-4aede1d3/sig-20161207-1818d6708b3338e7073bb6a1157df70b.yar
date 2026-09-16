rule sig_20161207_1818d6708b3338e7073bb6a1157df70b {
  meta:
    description = "datamaliciousorder - file 20161207_1818d6708b3338e7073bb6a1157df70b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "224b5b54fdd0be8b358a8683ccc79532ff90c002929ffb9dcc4c209fab86d8b4"

  strings:
    $s1 = "var vGs3 = new Function(\"vNXn3\", '{return vNXn3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vXFd2 = new Function(\"vNX" ascii
    $s2 = " = new Date();vPe5[\"setUTCFullYear\"](\"2003\");if (vPe5.getUTCFullYear().toString(10) == \"2003\") {var vAp3 = vNXn3.split(\"#" ascii
    $s3 = "var vGs3 = new Function(\"vNXn3\", '{return vNXn3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vXFd2 = new Function(\"vNX" ascii
    $s4 = "return vAp3.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}