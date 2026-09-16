rule TTP_XOR_QUAD_CurrentVersionRun_0249 {
  strings:
    $key_0249 = { 51 26 [2] 75 28 [2] 5e 04 [2] 70 26 [2] 64 3d [2] 6b 27 [2] 75 3a [2] 77 3b [2] 6c 3d [2] 70 3a [2] 6c 15 }

  condition:
    any of them
}