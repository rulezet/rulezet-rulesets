rule TTP_XOR_QUAD_CurrentVersionRun_1937 {
  strings:
    $key_1937 = { 4a 58 [2] 6e 56 [2] 45 7a [2] 6b 58 [2] 7f 43 [2] 70 59 [2] 6e 44 [2] 6c 45 [2] 77 43 [2] 6b 44 [2] 77 6b }

  condition:
    any of them
}