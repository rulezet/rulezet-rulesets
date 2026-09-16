rule sig_20161206_08d466411ca7b38933d9490e2e742366 {
  meta:
    description = "datamaliciousorder - file 20161206_08d466411ca7b38933d9490e2e742366.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "338a5ca7e14aaf17b43bdbbd5c79b00c4b72ec0d5669127c52fda3db9f2ba7ad"

  strings:
    $s1 = "var vFIh4 = new Function(\"s\", '{var vLd0 = new Date();vLd0[\"setUTCFullYear\"](\"2003\");if (vLd0.getUTCFullYear().toString(10" ascii
    $s2 = "var vFIh4 = new Function(\"s\", '{var vLd0 = new Date();vLd0[\"setUTCFullYear\"](\"2003\");if (vLd0.getUTCFullYear().toString(10" ascii
    $s3 = "function vQc9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "2003\") {var vVz4 = s.split(\"##\"); return vVz4.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}