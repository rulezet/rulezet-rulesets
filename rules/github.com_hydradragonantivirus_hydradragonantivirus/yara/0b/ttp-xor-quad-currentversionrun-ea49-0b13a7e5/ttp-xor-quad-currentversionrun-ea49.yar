rule TTP_XOR_QUAD_CurrentVersionRun_ea49 {
  strings:
    $key_ea49 = { b9 26 [2] 9d 28 [2] b6 04 [2] 98 26 [2] 8c 3d [2] 83 27 [2] 9d 3a [2] 9f 3b [2] 84 3d [2] 98 3a [2] 84 15 }

  condition:
    any of them
}