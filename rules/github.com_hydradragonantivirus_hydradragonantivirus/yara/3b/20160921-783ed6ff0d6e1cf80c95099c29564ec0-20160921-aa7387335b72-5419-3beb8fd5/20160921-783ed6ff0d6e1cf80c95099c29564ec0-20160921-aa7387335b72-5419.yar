rule _20160921_783ed6ff0d6e1cf80c95099c29564ec0_20160921_aa7387335b72_5419 {
  meta:
    description = "datamaliciousorder - from files 20160921_783ed6ff0d6e1cf80c95099c29564ec0.js, 20160921_aa7387335b72c30a3b2a33711bac8907.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "91c59edb0e2a43b5780f865f87a5462b55dab1281045b0a38b38ac155b7d34b6"
    hash2       = "96ff6fd5b079de518bd1ded811f4e98bcf45211a849900012beeb7e498b7b721"

  strings:
    $s1 = "k(){return \"XHj\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Xg\";" ascii
    $s2 = "n fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"" ascii
    $s3 = "nction fuck(){return \"IOs\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){retu" ascii
    $s4 = "rn \"OQr\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(f" ascii
    $s5 = "fuck(){return \"Tv\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"FJs" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}