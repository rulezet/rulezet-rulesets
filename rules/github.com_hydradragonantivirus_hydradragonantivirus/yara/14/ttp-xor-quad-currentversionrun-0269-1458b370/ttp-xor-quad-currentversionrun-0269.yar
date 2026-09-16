rule TTP_XOR_QUAD_CurrentVersionRun_0269 {
  strings:
    $key_0269 = { 51 06 [2] 75 08 [2] 5e 24 [2] 70 06 [2] 64 1d [2] 6b 07 [2] 75 1a [2] 77 1b [2] 6c 1d [2] 70 1a [2] 6c 35 }

  condition:
    any of them
}