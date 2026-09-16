rule TTP_XOR_QUAD_CurrentVersionRun_1c19 {
  strings:
    $key_1c19 = { 4f 76 [2] 6b 78 [2] 40 54 [2] 6e 76 [2] 7a 6d [2] 75 77 [2] 6b 6a [2] 69 6b [2] 72 6d [2] 6e 6a [2] 72 45 }

  condition:
    any of them
}