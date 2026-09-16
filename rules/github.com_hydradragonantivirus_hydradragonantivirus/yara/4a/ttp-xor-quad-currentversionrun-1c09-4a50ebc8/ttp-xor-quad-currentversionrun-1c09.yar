rule TTP_XOR_QUAD_CurrentVersionRun_1c09 {
  strings:
    $key_1c09 = { 4f 66 [2] 6b 68 [2] 40 44 [2] 6e 66 [2] 7a 7d [2] 75 67 [2] 6b 7a [2] 69 7b [2] 72 7d [2] 6e 7a [2] 72 55 }

  condition:
    any of them
}