rule TTP_XOR_QUAD_CurrentVersionRun_3237 {
  strings:
    $key_3237 = { 61 58 [2] 45 56 [2] 6e 7a [2] 40 58 [2] 54 43 [2] 5b 59 [2] 45 44 [2] 47 45 [2] 5c 43 [2] 40 44 [2] 5c 6b }

  condition:
    any of them
}