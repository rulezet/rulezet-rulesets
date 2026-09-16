rule TTP_XOR_QUAD_CurrentVersionRun_0537 {
  strings:
    $key_0537 = { 56 58 [2] 72 56 [2] 59 7a [2] 77 58 [2] 63 43 [2] 6c 59 [2] 72 44 [2] 70 45 [2] 6b 43 [2] 77 44 [2] 6b 6b }

  condition:
    any of them
}