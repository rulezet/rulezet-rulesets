rule TTP_XOR_QUAD_CurrentVersionRun_4c65 {
  strings:
    $key_4c65 = { 1f 0a [2] 3b 04 [2] 10 28 [2] 3e 0a [2] 2a 11 [2] 25 0b [2] 3b 16 [2] 39 17 [2] 22 11 [2] 3e 16 [2] 22 39 }

  condition:
    any of them
}