rule TTP_XOR_QUAD_CurrentVersionRun_7c09 {
  strings:
    $key_7c09 = { 2f 66 [2] 0b 68 [2] 20 44 [2] 0e 66 [2] 1a 7d [2] 15 67 [2] 0b 7a [2] 09 7b [2] 12 7d [2] 0e 7a [2] 12 55 }

  condition:
    any of them
}