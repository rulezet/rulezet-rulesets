rule TTP_XOR_QUAD_CurrentVersionRun_0837 {
  strings:
    $key_0837 = { 5b 58 [2] 7f 56 [2] 54 7a [2] 7a 58 [2] 6e 43 [2] 61 59 [2] 7f 44 [2] 7d 45 [2] 66 43 [2] 7a 44 [2] 66 6b }

  condition:
    any of them
}