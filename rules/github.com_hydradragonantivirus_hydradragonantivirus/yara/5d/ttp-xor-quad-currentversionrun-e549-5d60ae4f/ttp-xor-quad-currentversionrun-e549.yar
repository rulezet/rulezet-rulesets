rule TTP_XOR_QUAD_CurrentVersionRun_e549 {
  strings:
    $key_e549 = { b6 26 [2] 92 28 [2] b9 04 [2] 97 26 [2] 83 3d [2] 8c 27 [2] 92 3a [2] 90 3b [2] 8b 3d [2] 97 3a [2] 8b 15 }

  condition:
    any of them
}