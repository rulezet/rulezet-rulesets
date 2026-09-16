rule TTP_XOR_QUAD_CurrentVersionRun_5535 {
  strings:
    $key_5535 = { 06 5a [2] 22 54 [2] 09 78 [2] 27 5a [2] 33 41 [2] 3c 5b [2] 22 46 [2] 20 47 [2] 3b 41 [2] 27 46 [2] 3b 69 }

  condition:
    any of them
}