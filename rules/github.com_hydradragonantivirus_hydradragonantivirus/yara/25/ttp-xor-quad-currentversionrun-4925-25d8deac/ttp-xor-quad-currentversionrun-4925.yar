rule TTP_XOR_QUAD_CurrentVersionRun_4925 {
  strings:
    $key_4925 = { 1a 4a [2] 3e 44 [2] 15 68 [2] 3b 4a [2] 2f 51 [2] 20 4b [2] 3e 56 [2] 3c 57 [2] 27 51 [2] 3b 56 [2] 27 79 }

  condition:
    any of them
}