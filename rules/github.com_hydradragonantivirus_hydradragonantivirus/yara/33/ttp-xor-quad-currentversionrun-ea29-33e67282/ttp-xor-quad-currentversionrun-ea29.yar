rule TTP_XOR_QUAD_CurrentVersionRun_ea29 {
  strings:
    $key_ea29 = { b9 46 [2] 9d 48 [2] b6 64 [2] 98 46 [2] 8c 5d [2] 83 47 [2] 9d 5a [2] 9f 5b [2] 84 5d [2] 98 5a [2] 84 75 }

  condition:
    any of them
}