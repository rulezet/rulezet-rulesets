rule TTP_XOR_QUAD_CurrentVersionRun_1c15 {
  strings:
    $key_1c15 = { 4f 7a [2] 6b 74 [2] 40 58 [2] 6e 7a [2] 7a 61 [2] 75 7b [2] 6b 66 [2] 69 67 [2] 72 61 [2] 6e 66 [2] 72 49 }

  condition:
    any of them
}