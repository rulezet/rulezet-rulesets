rule TTP_XOR_QUAD_CurrentVersionRun_3537 {
  strings:
    $key_3537 = { 66 58 [2] 42 56 [2] 69 7a [2] 47 58 [2] 53 43 [2] 5c 59 [2] 42 44 [2] 40 45 [2] 5b 43 [2] 47 44 [2] 5b 6b }

  condition:
    any of them
}