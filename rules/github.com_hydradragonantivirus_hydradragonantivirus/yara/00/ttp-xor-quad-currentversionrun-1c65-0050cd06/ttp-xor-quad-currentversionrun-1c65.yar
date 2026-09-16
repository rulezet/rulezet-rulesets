rule TTP_XOR_QUAD_CurrentVersionRun_1c65 {
  strings:
    $key_1c65 = { 4f 0a [2] 6b 04 [2] 40 28 [2] 6e 0a [2] 7a 11 [2] 75 0b [2] 6b 16 [2] 69 17 [2] 72 11 [2] 6e 16 [2] 72 39 }

  condition:
    any of them
}