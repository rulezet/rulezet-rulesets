rule TTP_XOR_QUAD_CurrentVersionRun_ea73 {
  strings:
    $key_ea73 = { b9 1c [2] 9d 12 [2] b6 3e [2] 98 1c [2] 8c 07 [2] 83 1d [2] 9d 00 [2] 9f 01 [2] 84 07 [2] 98 00 [2] 84 2f }

  condition:
    any of them
}