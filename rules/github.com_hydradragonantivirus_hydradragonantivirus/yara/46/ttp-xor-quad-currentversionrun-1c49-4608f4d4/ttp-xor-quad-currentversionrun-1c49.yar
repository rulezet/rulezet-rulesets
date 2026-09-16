rule TTP_XOR_QUAD_CurrentVersionRun_1c49 {
  strings:
    $key_1c49 = { 4f 26 [2] 6b 28 [2] 40 04 [2] 6e 26 [2] 7a 3d [2] 75 27 [2] 6b 3a [2] 69 3b [2] 72 3d [2] 6e 3a [2] 72 15 }

  condition:
    any of them
}