rule _20160921_7caba45960de8ab0904dc3a8514f2614_20160921_bd6b4f506f52_5437 {
  meta:
    description = "datamaliciousorder - from files 20160921_7caba45960de8ab0904dc3a8514f2614.js, 20160921_bd6b4f506f527835a48516850a16c1a6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f07b11e4aaeb00f3fa8863261ca37d382057c7775579fae2a5744dcfdb99cd95"
    hash2       = "ccc844c2bc8943a231b37e8fbf1d55bab57686844fc9486bd597d3b00ae72c70"

  strings:
    $s1 = "turn \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"KVh\";})()," ascii
    $s2 = ",(function fuck(){return \"GJx\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){" ascii
    $s3 = "on fuck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"To\";})(),(function fuck(){return " ascii
    $s4 = "\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"DRx\";})(),(function f" ascii
    $s5 = "k(){return \"Sx\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Ot\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}