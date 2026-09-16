rule TTP_XOR_QUAD_CurrentVersionRun_7249 {
  strings:
    $key_7249 = { 21 26 [2] 05 28 [2] 2e 04 [2] 00 26 [2] 14 3d [2] 1b 27 [2] 05 3a [2] 07 3b [2] 1c 3d [2] 00 3a [2] 1c 15 }

  condition:
    any of them
}