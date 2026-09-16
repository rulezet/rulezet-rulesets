rule TTP_XOR_QUAD_CurrentVersionRun_7905 {
  strings:
    $key_7905 = { 2a 6a [2] 0e 64 [2] 25 48 [2] 0b 6a [2] 1f 71 [2] 10 6b [2] 0e 76 [2] 0c 77 [2] 17 71 [2] 0b 76 [2] 17 59 }

  condition:
    any of them
}