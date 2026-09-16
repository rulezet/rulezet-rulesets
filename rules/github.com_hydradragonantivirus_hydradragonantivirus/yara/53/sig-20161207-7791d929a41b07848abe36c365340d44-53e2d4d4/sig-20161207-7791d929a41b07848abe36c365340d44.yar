rule sig_20161207_7791d929a41b07848abe36c365340d44 {
  meta:
    description = "datamaliciousorder - file 20161207_7791d929a41b07848abe36c365340d44.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9571173e2b2638b72a176337dc73eff5a70e29c7db79a7d07a1946a237e8f578"

  strings:
    $s1 = "var vPf6 = new Function(\"vAa2\", '{var vPQb2 = new Date();vPQb2[\"setUTCFullYear\"](\"2003\");if (vPQb2.getUTCFullYear().toStri" ascii
    $s2 = "var vPf6 = new Function(\"vAa2\", '{var vPQb2 = new Date();vPQb2[\"setUTCFullYear\"](\"2003\");if (vPQb2.getUTCFullYear().toStri" ascii
    $s3 = "var vYp3 = new Function(\"vAa2\", '{return vAa2.split(\",\").join(\"\");};');" fullword ascii
    $s4 = " == \"2003\") {var vBk4 = vAa2.split(\"###\"); return vBk4.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}