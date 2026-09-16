rule TTP_XOR_QUAD_CurrentVersionRun_4c09 {
  strings:
    $key_4c09 = { 1f 66 [2] 3b 68 [2] 10 44 [2] 3e 66 [2] 2a 7d [2] 25 67 [2] 3b 7a [2] 39 7b [2] 22 7d [2] 3e 7a [2] 22 55 }

  condition:
    any of them
}