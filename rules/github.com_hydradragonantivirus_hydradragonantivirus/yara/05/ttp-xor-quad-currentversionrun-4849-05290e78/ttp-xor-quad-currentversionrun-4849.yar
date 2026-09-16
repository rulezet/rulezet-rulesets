rule TTP_XOR_QUAD_CurrentVersionRun_4849 {
  strings:
    $key_4849 = { 1b 26 [2] 3f 28 [2] 14 04 [2] 3a 26 [2] 2e 3d [2] 21 27 [2] 3f 3a [2] 3d 3b [2] 26 3d [2] 3a 3a [2] 26 15 }

  condition:
    any of them
}