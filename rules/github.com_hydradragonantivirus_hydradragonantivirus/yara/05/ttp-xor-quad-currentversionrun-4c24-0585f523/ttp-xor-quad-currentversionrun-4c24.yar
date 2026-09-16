rule TTP_XOR_QUAD_CurrentVersionRun_4c24 {
  strings:
    $key_4c24 = { 1f 4b [2] 3b 45 [2] 10 69 [2] 3e 4b [2] 2a 50 [2] 25 4a [2] 3b 57 [2] 39 56 [2] 22 50 [2] 3e 57 [2] 22 78 }

  condition:
    any of them
}