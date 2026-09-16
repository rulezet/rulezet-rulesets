rule TTP_XOR_QUAD_CurrentVersionRun_7749 {
  strings:
    $key_7749 = { 24 26 [2] 00 28 [2] 2b 04 [2] 05 26 [2] 11 3d [2] 1e 27 [2] 00 3a [2] 02 3b [2] 19 3d [2] 05 3a [2] 19 15 }

  condition:
    any of them
}