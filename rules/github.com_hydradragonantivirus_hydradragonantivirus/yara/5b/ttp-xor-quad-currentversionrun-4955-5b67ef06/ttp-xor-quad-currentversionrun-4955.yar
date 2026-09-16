rule TTP_XOR_QUAD_CurrentVersionRun_4955 {
  strings:
    $key_4955 = { 1a 3a [2] 3e 34 [2] 15 18 [2] 3b 3a [2] 2f 21 [2] 20 3b [2] 3e 26 [2] 3c 27 [2] 27 21 [2] 3b 26 [2] 27 09 }

  condition:
    any of them
}