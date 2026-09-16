rule TTP_XOR_QUAD_CurrentVersionRun_4c0b {
  strings:
    $key_4c0b = { 1f 64 [2] 3b 6a [2] 10 46 [2] 3e 64 [2] 2a 7f [2] 25 65 [2] 3b 78 [2] 39 79 [2] 22 7f [2] 3e 78 [2] 22 57 }

  condition:
    any of them
}