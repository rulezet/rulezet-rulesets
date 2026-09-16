rule TTP_XOR_QUAD_CurrentVersionRun_5037 {
  strings:
    $key_5037 = { 03 58 [2] 27 56 [2] 0c 7a [2] 22 58 [2] 36 43 [2] 39 59 [2] 27 44 [2] 25 45 [2] 3e 43 [2] 22 44 [2] 3e 6b }

  condition:
    any of them
}