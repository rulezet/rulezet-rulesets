rule TTP_XOR_QUAD_CurrentVersionRun_ea59 {
  strings:
    $key_ea59 = { b9 36 [2] 9d 38 [2] b6 14 [2] 98 36 [2] 8c 2d [2] 83 37 [2] 9d 2a [2] 9f 2b [2] 84 2d [2] 98 2a [2] 84 05 }

  condition:
    any of them
}