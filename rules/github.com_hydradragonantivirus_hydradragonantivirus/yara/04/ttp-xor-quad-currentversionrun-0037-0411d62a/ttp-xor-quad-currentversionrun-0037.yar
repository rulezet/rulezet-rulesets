rule TTP_XOR_QUAD_CurrentVersionRun_0037 {
  strings:
    $key_0037 = { 53 58 [2] 77 56 [2] 5c 7a [2] 72 58 [2] 66 43 [2] 69 59 [2] 77 44 [2] 75 45 [2] 6e 43 [2] 72 44 [2] 6e 6b }

  condition:
    any of them
}