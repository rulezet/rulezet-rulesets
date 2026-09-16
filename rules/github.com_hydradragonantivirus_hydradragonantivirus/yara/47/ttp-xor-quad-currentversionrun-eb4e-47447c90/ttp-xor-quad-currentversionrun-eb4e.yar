rule TTP_XOR_QUAD_CurrentVersionRun_eb4e {
  strings:
    $key_eb4e = { b8 21 [2] 9c 2f [2] b7 03 [2] 99 21 [2] 8d 3a [2] 82 20 [2] 9c 3d [2] 9e 3c [2] 85 3a [2] 99 3d [2] 85 12 }

  condition:
    any of them
}