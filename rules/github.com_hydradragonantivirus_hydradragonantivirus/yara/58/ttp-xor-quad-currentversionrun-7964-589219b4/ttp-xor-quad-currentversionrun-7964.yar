rule TTP_XOR_QUAD_CurrentVersionRun_7964 {
  strings:
    $key_7964 = { 2a 0b [2] 0e 05 [2] 25 29 [2] 0b 0b [2] 1f 10 [2] 10 0a [2] 0e 17 [2] 0c 16 [2] 17 10 [2] 0b 17 [2] 17 38 }

  condition:
    any of them
}