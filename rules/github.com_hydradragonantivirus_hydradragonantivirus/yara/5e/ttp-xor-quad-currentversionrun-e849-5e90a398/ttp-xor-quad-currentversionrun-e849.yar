rule TTP_XOR_QUAD_CurrentVersionRun_e849 {
  strings:
    $key_e849 = { bb 26 [2] 9f 28 [2] b4 04 [2] 9a 26 [2] 8e 3d [2] 81 27 [2] 9f 3a [2] 9d 3b [2] 86 3d [2] 9a 3a [2] 86 15 }

  condition:
    any of them
}