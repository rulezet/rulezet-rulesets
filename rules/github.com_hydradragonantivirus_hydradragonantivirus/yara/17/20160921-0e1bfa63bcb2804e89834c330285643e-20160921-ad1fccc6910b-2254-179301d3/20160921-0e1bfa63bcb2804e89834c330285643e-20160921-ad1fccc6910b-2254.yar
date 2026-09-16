rule _20160921_0e1bfa63bcb2804e89834c330285643e_20160921_ad1fccc6910b_2254 {
  meta:
    description = "datamaliciousorder - from files 20160921_0e1bfa63bcb2804e89834c330285643e.js, 20160921_ad1fccc6910bd9c4a47aa9bd3e9239da.js, 20160921_b5efb4ba3e712545d64a2d00b3dcd76e.js, 20160921_e39622eeb1da8fbbf03ca86989251a47.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d58b57cb825244d35e22402fcf08c9ababcc51eb72a7913c47dbb2143171df32"
    hash2       = "a49fc1cb85eaa58b7c63197e9fd25224f63dcb6c86b906933f698898634ead3e"
    hash3       = "ff8ef85b589636068d365f9ee4a0b9c7119baeb269d0a34c9810fca4b3faf1cf"
    hash4       = "e0b1660f1c95284f1a0f8062a1f16e26aa3d58e3fa4cf47fc04824d02b754a56"

  strings:
    $s1 = "),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"USf\";})(),(function fuck(){" ascii
    $s2 = "k(){return \"Jh\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"USf\";}" ascii
    $s3 = "rn \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Et\";})(),(f" ascii
    $s4 = ";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"MUs\";})(),(function fu" ascii
    $s5 = "(){return \"Jh\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"USf\";})" ascii
    $s6 = ")(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Hs\";})(),(function fuck" ascii
    $s7 = "rn \"Et\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(f" ascii
    $s8 = "nction fuck(){return \"Et\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}