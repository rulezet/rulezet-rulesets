rule TTP_XOR_QUAD_CurrentVersionRun_1c79 {
  strings:
    $key_1c79 = { 4f 16 [2] 6b 18 [2] 40 34 [2] 6e 16 [2] 7a 0d [2] 75 17 [2] 6b 0a [2] 69 0b [2] 72 0d [2] 6e 0a [2] 72 25 }

  condition:
    any of them
}