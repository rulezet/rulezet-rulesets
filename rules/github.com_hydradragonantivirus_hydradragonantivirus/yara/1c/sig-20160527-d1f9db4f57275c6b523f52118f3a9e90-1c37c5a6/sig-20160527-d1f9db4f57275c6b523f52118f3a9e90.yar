rule sig_20160527_d1f9db4f57275c6b523f52118f3a9e90 {
  meta:
    description = "datamaliciousorder - file 20160527_d1f9db4f57275c6b523f52118f3a9e90.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "61ffd7aaa49b7357362e6687a690f621bddea7847c180e286fff32bc193ea9d4"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<a9Wel5G5.length;i++)if(i%2==0)x.push(a9Wel5G5[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}