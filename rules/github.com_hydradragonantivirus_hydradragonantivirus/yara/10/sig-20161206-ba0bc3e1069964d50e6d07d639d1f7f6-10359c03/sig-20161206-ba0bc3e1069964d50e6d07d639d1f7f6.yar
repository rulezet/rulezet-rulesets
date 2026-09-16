rule sig_20161206_ba0bc3e1069964d50e6d07d639d1f7f6 {
  meta:
    description = "datamaliciousorder - file 20161206_ba0bc3e1069964d50e6d07d639d1f7f6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4225b08df61394bae23119bd419c39c7379458cfa9633d745593a5ff7ae81c09"

  strings:
    $s1 = "var vVIv1 = new Function(\"s\", '{var vSg6 = new Date();vSg6[\"setUTCFullYear\"](\"2003\");if (vSg6.getUTCFullYear().toString(10" ascii
    $s2 = "var vVIv1 = new Function(\"s\", '{var vSg6 = new Date();vSg6[\"setUTCFullYear\"](\"2003\");if (vSg6.getUTCFullYear().toString(10" ascii
    $s3 = "function vYKk9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "2003\") {var vOp0 = s.split(\"##\"); return vOp0.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}