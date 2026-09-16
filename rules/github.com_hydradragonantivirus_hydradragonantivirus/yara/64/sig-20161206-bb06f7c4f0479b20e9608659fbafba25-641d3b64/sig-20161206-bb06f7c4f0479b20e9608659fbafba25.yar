rule sig_20161206_bb06f7c4f0479b20e9608659fbafba25 {
  meta:
    description = "datamaliciousorder - file 20161206_bb06f7c4f0479b20e9608659fbafba25.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf84b4b50865f5099252281c656bcc512533c30fbaabcde44da071e5fe37d35c"

  strings:
    $s1 = "var vPc6 = new Function(\"s\", '{var vAk3 = new Date();vAk3[\"setUTCFullYear\"](\"2003\");if (vAk3.getUTCFullYear().toString(10)" ascii
    $s2 = "var vPc6 = new Function(\"s\", '{var vAk3 = new Date();vAk3[\"setUTCFullYear\"](\"2003\");if (vAk3.getUTCFullYear().toString(10)" ascii
    $s3 = "003\") {var vDv2 = s.split(\"##\"); return vDv2.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vUb4(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}