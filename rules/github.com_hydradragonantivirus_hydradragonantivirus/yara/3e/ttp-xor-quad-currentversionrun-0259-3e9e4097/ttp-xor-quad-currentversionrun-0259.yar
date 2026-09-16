rule TTP_XOR_QUAD_CurrentVersionRun_0259 {
  strings:
    $key_0259 = { 51 36 [2] 75 38 [2] 5e 14 [2] 70 36 [2] 64 2d [2] 6b 37 [2] 75 2a [2] 77 2b [2] 6c 2d [2] 70 2a [2] 6c 05 }

  condition:
    any of them
}