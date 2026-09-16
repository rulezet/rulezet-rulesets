rule TTP_XOR_QUAD_CurrentVersionRun_4049 {
  strings:
    $key_4049 = { 13 26 [2] 37 28 [2] 1c 04 [2] 32 26 [2] 26 3d [2] 29 27 [2] 37 3a [2] 35 3b [2] 2e 3d [2] 32 3a [2] 2e 15 }

  condition:
    any of them
}