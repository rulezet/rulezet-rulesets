rule sig_20161207_38735c0632c27f7c4cca4739a191a39e {
  meta:
    description = "datamaliciousorder - file 20161207_38735c0632c27f7c4cca4739a191a39e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "435efe0349edc84920adfde0813a3553ffc90d71e9e028ed6f1bc63b7451424c"

  strings:
    $s1 = "var vWCd0 = new Function(\"vVv6\", '{var vZu3 = new Date();vZu3[\"setUTCFullYear\"](\"2003\");if (vZu3.getUTCFullYear().toString" ascii
    $s2 = "var vWCd0 = new Function(\"vVv6\", '{var vZu3 = new Date();vZu3[\"setUTCFullYear\"](\"2003\");if (vZu3.getUTCFullYear().toString" ascii
    $s3 = "var vWa7 = new Function(\"vVv6\", '{return vVv6.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "= \"2003\") {var vCUg4 = vVv6.split(\"###\"); return vCUg4.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}