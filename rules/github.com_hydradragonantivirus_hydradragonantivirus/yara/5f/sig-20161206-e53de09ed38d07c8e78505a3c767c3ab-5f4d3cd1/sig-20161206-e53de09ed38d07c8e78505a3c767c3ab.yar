rule sig_20161206_e53de09ed38d07c8e78505a3c767c3ab {
  meta:
    description = "datamaliciousorder - file 20161206_e53de09ed38d07c8e78505a3c767c3ab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "06216212435986845893e5425c24bbdf68adaacd0be61092dd3dfe67af78531c"

  strings:
    $s1 = "var vSy0 = new Function(\"s\", '{var vKYc9 = new Date();vKYc9[\"setUTCFullYear\"](\"2003\");if (vKYc9.getUTCFullYear().toString(" ascii
    $s2 = "var vSy0 = new Function(\"s\", '{var vKYc9 = new Date();vKYc9[\"setUTCFullYear\"](\"2003\");if (vKYc9.getUTCFullYear().toString(" ascii
    $s3 = "function vGu0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = " \"2003\") {var vKDc5 = s.split(\"##\"); return vKDc5.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}