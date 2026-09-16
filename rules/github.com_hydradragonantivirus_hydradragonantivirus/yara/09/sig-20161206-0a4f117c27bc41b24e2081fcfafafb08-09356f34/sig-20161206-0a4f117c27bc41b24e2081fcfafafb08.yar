rule sig_20161206_0a4f117c27bc41b24e2081fcfafafb08 {
  meta:
    description = "datamaliciousorder - file 20161206_0a4f117c27bc41b24e2081fcfafafb08.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46a9c140307a6fd9e0a3776553f468a5346c8866e257f3eba6d8342214a0ec4e"

  strings:
    $s1 = "var vEPx8 = new Function(\"s\", '{var vVo3 = new Date();vVo3[\"setUTCFullYear\"](\"2003\");if (vVo3.getUTCFullYear().toString(10" ascii
    $s2 = "var vEPx8 = new Function(\"s\", '{var vVo3 = new Date();vVo3[\"setUTCFullYear\"](\"2003\");if (vVo3.getUTCFullYear().toString(10" ascii
    $s3 = "2003\") {var vVi1 = s.split(\"##\"); return vVi1.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vNJs0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}