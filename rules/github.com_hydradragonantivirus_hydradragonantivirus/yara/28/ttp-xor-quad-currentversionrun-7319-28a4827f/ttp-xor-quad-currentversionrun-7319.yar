rule TTP_XOR_QUAD_CurrentVersionRun_7319 {
  strings:
    $key_7319 = { 20 76 [2] 04 78 [2] 2f 54 [2] 01 76 [2] 15 6d [2] 1a 77 [2] 04 6a [2] 06 6b [2] 1d 6d [2] 01 6a [2] 1d 45 }

  condition:
    any of them
}