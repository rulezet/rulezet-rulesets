rule sig_20161206_5d39f371be09790ce7d59f89ec5f47cb {
  meta:
    description = "datamaliciousorder - file 20161206_5d39f371be09790ce7d59f89ec5f47cb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef24b0b79c3e4f9eb24177ee381ded067be83d8c872057d91c9b14c3b3d6107f"

  strings:
    $s1 = "var vCNb2 = new Function(\"s\", '{var vFd6 = new Date();vFd6[\"setUTCFullYear\"](\"2003\");if (vFd6.getUTCFullYear().toString(10" ascii
    $s2 = "var vCNb2 = new Function(\"s\", '{var vFd6 = new Date();vFd6[\"setUTCFullYear\"](\"2003\");if (vFd6.getUTCFullYear().toString(10" ascii
    $s3 = "function vOp1(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "2003\") {var vZSp3 = s.split(\"##\"); return vZSp3.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}