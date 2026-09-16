rule TTP_XOR_QUAD_CurrentVersionRun_5237 {
  strings:
    $key_5237 = { 01 58 [2] 25 56 [2] 0e 7a [2] 20 58 [2] 34 43 [2] 3b 59 [2] 25 44 [2] 27 45 [2] 3c 43 [2] 20 44 [2] 3c 6b }

  condition:
    any of them
}