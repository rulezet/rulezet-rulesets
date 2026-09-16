rule TTP_XOR_QUAD_CurrentVersionRun_ea58 {
  strings:
    $key_ea58 = { b9 37 [2] 9d 39 [2] b6 15 [2] 98 37 [2] 8c 2c [2] 83 36 [2] 9d 2b [2] 9f 2a [2] 84 2c [2] 98 2b [2] 84 04 }

  condition:
    any of them
}