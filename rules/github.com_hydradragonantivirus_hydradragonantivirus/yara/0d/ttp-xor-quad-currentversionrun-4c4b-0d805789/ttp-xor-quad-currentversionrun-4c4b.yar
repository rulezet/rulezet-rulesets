rule TTP_XOR_QUAD_CurrentVersionRun_4c4b {
  strings:
    $key_4c4b = { 1f 24 [2] 3b 2a [2] 10 06 [2] 3e 24 [2] 2a 3f [2] 25 25 [2] 3b 38 [2] 39 39 [2] 22 3f [2] 3e 38 [2] 22 17 }

  condition:
    any of them
}