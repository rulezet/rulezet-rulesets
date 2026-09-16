rule TTP_XOR_QUAD_CurrentVersionRun_ea5f {
  strings:
    $key_ea5f = { b9 30 [2] 9d 3e [2] b6 12 [2] 98 30 [2] 8c 2b [2] 83 31 [2] 9d 2c [2] 9f 2d [2] 84 2b [2] 98 2c [2] 84 03 }

  condition:
    any of them
}