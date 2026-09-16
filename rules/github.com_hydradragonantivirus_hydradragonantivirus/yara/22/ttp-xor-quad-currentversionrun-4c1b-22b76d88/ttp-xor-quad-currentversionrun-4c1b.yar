rule TTP_XOR_QUAD_CurrentVersionRun_4c1b {
  strings:
    $key_4c1b = { 1f 74 [2] 3b 7a [2] 10 56 [2] 3e 74 [2] 2a 6f [2] 25 75 [2] 3b 68 [2] 39 69 [2] 22 6f [2] 3e 68 [2] 22 47 }

  condition:
    any of them
}