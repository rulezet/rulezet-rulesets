rule TTP_XOR_QUAD_CurrentVersionRun_4c39 {
  strings:
    $key_4c39 = { 1f 56 [2] 3b 58 [2] 10 74 [2] 3e 56 [2] 2a 4d [2] 25 57 [2] 3b 4a [2] 39 4b [2] 22 4d [2] 3e 4a [2] 22 65 }

  condition:
    any of them
}