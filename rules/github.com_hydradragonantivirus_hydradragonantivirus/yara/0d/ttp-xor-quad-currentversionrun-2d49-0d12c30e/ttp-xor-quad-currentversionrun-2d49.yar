rule TTP_XOR_QUAD_CurrentVersionRun_2d49 {
  strings:
    $key_2d49 = { 7e 26 [2] 5a 28 [2] 71 04 [2] 5f 26 [2] 4b 3d [2] 44 27 [2] 5a 3a [2] 58 3b [2] 43 3d [2] 5f 3a [2] 43 15 }

  condition:
    any of them
}