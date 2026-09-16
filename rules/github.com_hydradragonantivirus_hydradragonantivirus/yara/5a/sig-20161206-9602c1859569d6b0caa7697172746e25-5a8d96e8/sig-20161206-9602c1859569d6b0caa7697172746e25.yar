rule sig_20161206_9602c1859569d6b0caa7697172746e25 {
  meta:
    description = "datamaliciousorder - file 20161206_9602c1859569d6b0caa7697172746e25.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0c3024e4d75899aaf884352c3beb2de62efbdd43f82a93916f676e56988adced"

  strings:
    $s1 = "var vAm7 = new Function(\"s\", '{var vQi2 = new Date();vQi2[\"setUTCFullYear\"](\"2003\");if (vQi2.getUTCFullYear().toString(10)" ascii
    $s2 = "var vAm7 = new Function(\"s\", '{var vQi2 = new Date();vQi2[\"setUTCFullYear\"](\"2003\");if (vQi2.getUTCFullYear().toString(10)" ascii
    $s3 = "003\") {var vMZq0 = s.split(\"##\"); return vMZq0.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vJVa9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}