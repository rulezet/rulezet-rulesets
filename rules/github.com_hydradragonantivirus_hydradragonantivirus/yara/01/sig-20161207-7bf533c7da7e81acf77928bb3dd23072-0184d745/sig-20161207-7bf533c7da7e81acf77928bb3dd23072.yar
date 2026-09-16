rule sig_20161207_7bf533c7da7e81acf77928bb3dd23072 {
  meta:
    description = "datamaliciousorder - file 20161207_7bf533c7da7e81acf77928bb3dd23072.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "04b0bd83384ba8e766866b78aa781910cd4e58973f5ab6e260a677251f359ab4"

  strings:
    $s1 = "var vUn6 = new Function(\"vPQh4\", '{var vYIw7 = new Date();vYIw7[\"setUTCFullYear\"](\"2003\");if (vYIw7.getUTCFullYear().toStr" ascii
    $s2 = "var vUn6 = new Function(\"vPQh4\", '{var vYIw7 = new Date();vYIw7[\"setUTCFullYear\"](\"2003\");if (vYIw7.getUTCFullYear().toStr" ascii
    $s3 = ") == \"2003\") {var vMIo5 = vPQh4.split(\"###\"); return vMIo5.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vPp4 = new Function(\"vPQh4\", '{return vPQh4.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}