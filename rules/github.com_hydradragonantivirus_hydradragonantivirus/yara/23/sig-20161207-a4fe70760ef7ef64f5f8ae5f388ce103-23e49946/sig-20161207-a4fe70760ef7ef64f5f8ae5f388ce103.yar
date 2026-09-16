rule sig_20161207_a4fe70760ef7ef64f5f8ae5f388ce103 {
  meta:
    description = "datamaliciousorder - file 20161207_a4fe70760ef7ef64f5f8ae5f388ce103.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4aeac55b7ddb215e8cb5b078994d028bb75c1c73cc5d00486d83fddc90efe4cc"

  strings:
    $s1 = "var vNq7 = new Function(\"vQLi9\", '{var vXTw4 = new Date();vXTw4[\"setUTCFullYear\"](\"2003\");if (vXTw4.getUTCFullYear().toStr" ascii
    $s2 = "var vNq7 = new Function(\"vQLi9\", '{var vXTw4 = new Date();vXTw4[\"setUTCFullYear\"](\"2003\");if (vXTw4.getUTCFullYear().toStr" ascii
    $s3 = ") == \"2003\") {var vVh6 = vQLi9.split(\"###\"); return vVh6.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vIXl6 = new Function(\"vQLi9\", '{return vQLi9.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}