rule TTP_XOR_QUAD_CurrentVersionRun_ea4e {
  strings:
    $key_ea4e = { b9 21 [2] 9d 2f [2] b6 03 [2] 98 21 [2] 8c 3a [2] 83 20 [2] 9d 3d [2] 9f 3c [2] 84 3a [2] 98 3d [2] 84 12 }

  condition:
    any of them
}