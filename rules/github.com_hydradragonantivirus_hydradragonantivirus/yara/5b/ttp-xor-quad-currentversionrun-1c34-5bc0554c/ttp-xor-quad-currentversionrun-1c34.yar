rule TTP_XOR_QUAD_CurrentVersionRun_1c34 {
  strings:
    $key_1c34 = { 4f 5b [2] 6b 55 [2] 40 79 [2] 6e 5b [2] 7a 40 [2] 75 5a [2] 6b 47 [2] 69 46 [2] 72 40 [2] 6e 47 [2] 72 68 }

  condition:
    any of them
}