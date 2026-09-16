rule sig_20161207_41f50745f328f8b15c0607f670ed0081 {
  meta:
    description = "datamaliciousorder - file 20161207_41f50745f328f8b15c0607f670ed0081.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "63568e7b92eae1569987896748abdeddc81631a8f82dfb8853af9e31dd01ebdc"

  strings:
    $s1 = "var vJMl0 = new Function(\"vGLe5\", '{var vMa2 = new Date();vMa2[\"setUTCFullYear\"](\"2003\");if (vMa2.getUTCFullYear().toStrin" ascii
    $s2 = "var vJMl0 = new Function(\"vGLe5\", '{var vMa2 = new Date();vMa2[\"setUTCFullYear\"](\"2003\");if (vMa2.getUTCFullYear().toStrin" ascii
    $s3 = "== \"2003\") {var vYKb8 = vGLe5.split(\"###\"); return vYKb8.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vRRw6 = new Function(\"vGLe5\", '{return vGLe5.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}