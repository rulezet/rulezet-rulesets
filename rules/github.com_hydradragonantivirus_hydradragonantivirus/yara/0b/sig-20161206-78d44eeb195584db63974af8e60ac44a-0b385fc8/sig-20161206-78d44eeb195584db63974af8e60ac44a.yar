rule sig_20161206_78d44eeb195584db63974af8e60ac44a {
  meta:
    description = "datamaliciousorder - file 20161206_78d44eeb195584db63974af8e60ac44a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5765c385ffb85c0eab00e15c87f4eefa040c64ea6793776903aa843fd23269bf"

  strings:
    $s1 = "var vAv6 = new Function(\"s\", '{var vUHb8 = new Date();vUHb8[\"setUTCFullYear\"](\"2003\");if (vUHb8.getUTCFullYear().toString(" ascii
    $s2 = "var vAv6 = new Function(\"s\", '{var vUHb8 = new Date();vUHb8[\"setUTCFullYear\"](\"2003\");if (vUHb8.getUTCFullYear().toString(" ascii
    $s3 = "function vIJo0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = " \"2003\") {var vPl3 = s.split(\"##\"); return vPl3.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}