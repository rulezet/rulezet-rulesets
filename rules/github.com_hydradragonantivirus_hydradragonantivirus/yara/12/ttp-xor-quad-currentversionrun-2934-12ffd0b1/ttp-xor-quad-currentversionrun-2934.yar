rule TTP_XOR_QUAD_CurrentVersionRun_2934 {
  strings:
    $key_2934 = { 7a 5b [2] 5e 55 [2] 75 79 [2] 5b 5b [2] 4f 40 [2] 40 5a [2] 5e 47 [2] 5c 46 [2] 47 40 [2] 5b 47 [2] 47 68 }

  condition:
    any of them
}