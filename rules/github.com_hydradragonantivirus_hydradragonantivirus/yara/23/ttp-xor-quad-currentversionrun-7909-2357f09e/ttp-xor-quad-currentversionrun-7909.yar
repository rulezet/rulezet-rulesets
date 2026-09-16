rule TTP_XOR_QUAD_CurrentVersionRun_7909 {
  strings:
    $key_7909 = { 2a 66 [2] 0e 68 [2] 25 44 [2] 0b 66 [2] 1f 7d [2] 10 67 [2] 0e 7a [2] 0c 7b [2] 17 7d [2] 0b 7a [2] 17 55 }

  condition:
    any of them
}