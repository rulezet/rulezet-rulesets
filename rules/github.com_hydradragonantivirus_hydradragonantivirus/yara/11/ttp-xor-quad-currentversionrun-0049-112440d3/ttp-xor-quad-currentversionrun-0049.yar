rule TTP_XOR_QUAD_CurrentVersionRun_0049 {
  strings:
    $key_0049 = { 53 26 [2] 77 28 [2] 5c 04 [2] 72 26 [2] 66 3d [2] 69 27 [2] 77 3a [2] 75 3b [2] 6e 3d [2] 72 3a [2] 6e 15 }

  condition:
    any of them
}