rule TTP_XOR_QUAD_CurrentVersionRun_ed4e {
  strings:
    $key_ed4e = { be 21 [2] 9a 2f [2] b1 03 [2] 9f 21 [2] 8b 3a [2] 84 20 [2] 9a 3d [2] 98 3c [2] 83 3a [2] 9f 3d [2] 83 12 }

  condition:
    any of them
}