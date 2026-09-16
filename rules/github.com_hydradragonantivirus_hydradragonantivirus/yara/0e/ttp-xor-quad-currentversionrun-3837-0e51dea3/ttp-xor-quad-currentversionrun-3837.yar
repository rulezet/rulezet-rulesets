rule TTP_XOR_QUAD_CurrentVersionRun_3837 {
  strings:
    $key_3837 = { 6b 58 [2] 4f 56 [2] 64 7a [2] 4a 58 [2] 5e 43 [2] 51 59 [2] 4f 44 [2] 4d 45 [2] 56 43 [2] 4a 44 [2] 56 6b }

  condition:
    any of them
}