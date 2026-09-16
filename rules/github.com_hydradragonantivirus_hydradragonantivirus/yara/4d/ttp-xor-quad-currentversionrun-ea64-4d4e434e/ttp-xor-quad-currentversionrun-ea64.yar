rule TTP_XOR_QUAD_CurrentVersionRun_ea64 {
  strings:
    $key_ea64 = { b9 0b [2] 9d 05 [2] b6 29 [2] 98 0b [2] 8c 10 [2] 83 0a [2] 9d 17 [2] 9f 16 [2] 84 10 [2] 98 17 [2] 84 38 }

  condition:
    any of them
}