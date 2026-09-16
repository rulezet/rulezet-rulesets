rule sig_20161206_7163d7aa247942fb29aafe83aba489c1 {
  meta:
    description = "datamaliciousorder - file 20161206_7163d7aa247942fb29aafe83aba489c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "348c4873e30adf23619d128be9100df97b5ba6e525591bd2e31ee15bff9ea0fd"

  strings:
    $s1 = "var vWl4 = new Function(\"s\", '{var vYp5 = new Date();vYp5[\"setUTCFullYear\"](\"2003\");if (vYp5.getUTCFullYear().toString(10)" ascii
    $s2 = "var vWl4 = new Function(\"s\", '{var vYp5 = new Date();vYp5[\"setUTCFullYear\"](\"2003\");if (vYp5.getUTCFullYear().toString(10)" ascii
    $s3 = "003\") {var vMVp1 = s.split(\"##\"); return vMVp1.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vDf3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}