rule sig_20161207_e3ce1454effe9ce06ed7378aeff372de {
  meta:
    description = "datamaliciousorder - file 20161207_e3ce1454effe9ce06ed7378aeff372de.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79397e0980fc5a4e394f44dfdec5268c1e9d4d2f78bcea804627d49e7852a41a"

  strings:
    $s1 = "var vLLh8 = new Function(\"vMe1\", '{var vTg2 = new Date();vTg2[\"setUTCFullYear\"](\"2003\");if (vTg2.getUTCFullYear().toString" ascii
    $s2 = "var vLLh8 = new Function(\"vMe1\", '{var vTg2 = new Date();vTg2[\"setUTCFullYear\"](\"2003\");if (vTg2.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vHu9 = vMe1.split(\"###\"); return vHu9.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vTq2 = new Function(\"vMe1\", '{return vMe1.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}