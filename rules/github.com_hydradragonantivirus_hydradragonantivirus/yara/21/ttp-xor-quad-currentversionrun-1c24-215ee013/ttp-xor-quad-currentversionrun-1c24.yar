rule TTP_XOR_QUAD_CurrentVersionRun_1c24 {
  strings:
    $key_1c24 = { 4f 4b [2] 6b 45 [2] 40 69 [2] 6e 4b [2] 7a 50 [2] 75 4a [2] 6b 57 [2] 69 56 [2] 72 50 [2] 6e 57 [2] 72 78 }

  condition:
    any of them
}