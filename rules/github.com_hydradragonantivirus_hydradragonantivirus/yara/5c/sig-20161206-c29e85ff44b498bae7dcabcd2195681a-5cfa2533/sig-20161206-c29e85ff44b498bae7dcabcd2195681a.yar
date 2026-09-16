rule sig_20161206_c29e85ff44b498bae7dcabcd2195681a {
  meta:
    description = "datamaliciousorder - file 20161206_c29e85ff44b498bae7dcabcd2195681a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c196735e76856bff4c4abc57c5403556c11278f8b0077d108704c08423292bf"

  strings:
    $s1 = "var vOLl4 = new Function(\"s\", '{var vYa6 = new Date();vYa6[\"setUTCFullYear\"](\"2003\");if (vYa6.getUTCFullYear().toString(10" ascii
    $s2 = "var vOLl4 = new Function(\"s\", '{var vYa6 = new Date();vYa6[\"setUTCFullYear\"](\"2003\");if (vYa6.getUTCFullYear().toString(10" ascii
    $s3 = "function vMx0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "2003\") {var vTx5 = s.split(\"##\"); return vTx5.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}