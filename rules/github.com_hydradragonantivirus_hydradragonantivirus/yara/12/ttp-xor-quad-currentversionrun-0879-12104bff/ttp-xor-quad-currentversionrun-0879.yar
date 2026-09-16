rule TTP_XOR_QUAD_CurrentVersionRun_0879 {
  strings:
    $key_0879 = { 5b 16 [2] 7f 18 [2] 54 34 [2] 7a 16 [2] 6e 0d [2] 61 17 [2] 7f 0a [2] 7d 0b [2] 66 0d [2] 7a 0a [2] 66 25 }

  condition:
    any of them
}