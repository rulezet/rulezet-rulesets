rule sig_20161206_2ae0fa3ba5fe48018ba69160abe317a8 {
  meta:
    description = "datamaliciousorder - file 20161206_2ae0fa3ba5fe48018ba69160abe317a8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "51d76fd0b953f1f589115d9da202691f5b7585c20ecd3a9eeef4acb6089da18a"

  strings:
    $s1 = "var vIk1 = new Function(\"s\", '{var vXQt1 = new Date();vXQt1[\"setUTCFullYear\"](\"2003\");if (vXQt1.getUTCFullYear().toString(" ascii
    $s2 = "var vIk1 = new Function(\"s\", '{var vXQt1 = new Date();vXQt1[\"setUTCFullYear\"](\"2003\");if (vXQt1.getUTCFullYear().toString(" ascii
    $s3 = " \"2003\") {var vXHh4 = s.split(\"##\"); return vXHh4.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vVAs3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}