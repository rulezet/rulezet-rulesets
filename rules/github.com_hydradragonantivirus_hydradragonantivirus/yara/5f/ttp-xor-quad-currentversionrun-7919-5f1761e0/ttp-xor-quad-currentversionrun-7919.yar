rule TTP_XOR_QUAD_CurrentVersionRun_7919 {
  strings:
    $key_7919 = { 2a 76 [2] 0e 78 [2] 25 54 [2] 0b 76 [2] 1f 6d [2] 10 77 [2] 0e 6a [2] 0c 6b [2] 17 6d [2] 0b 6a [2] 17 45 }

  condition:
    any of them
}