rule TTP_XOR_QUAD_CurrentVersionRun_4c2b {
  strings:
    $key_4c2b = { 1f 44 [2] 3b 4a [2] 10 66 [2] 3e 44 [2] 2a 5f [2] 25 45 [2] 3b 58 [2] 39 59 [2] 22 5f [2] 3e 58 [2] 22 77 }

  condition:
    any of them
}