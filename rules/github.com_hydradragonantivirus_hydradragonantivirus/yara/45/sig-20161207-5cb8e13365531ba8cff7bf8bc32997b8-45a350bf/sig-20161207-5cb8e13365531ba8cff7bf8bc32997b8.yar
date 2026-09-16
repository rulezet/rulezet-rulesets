rule sig_20161207_5cb8e13365531ba8cff7bf8bc32997b8 {
  meta:
    description = "datamaliciousorder - file 20161207_5cb8e13365531ba8cff7bf8bc32997b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bec3af0a98fb70f9e01459354025bc1a072d87e40ea1e5e646a3ac89f085ee92"

  strings:
    $s1 = "var vHRz9 = new Function(\"vLl0\", '{return vLl0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vQTp7 = new Function(\"vLl0" ascii
    $s2 = "= new Date();vAUz0[\"setUTCFullYear\"](\"2003\");if (vAUz0.getUTCFullYear().toString(10) == \"2003\") {var vBd3 = vLl0.split(\"#" ascii
    $s3 = "return vBd3.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vHRz9 = new Function(\"vLl0\", '{return vLl0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vQTp7 = new Function(\"vLl0" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}