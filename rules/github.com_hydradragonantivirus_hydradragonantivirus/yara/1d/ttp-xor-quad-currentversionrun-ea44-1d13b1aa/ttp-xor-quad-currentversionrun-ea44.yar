rule TTP_XOR_QUAD_CurrentVersionRun_ea44 {
  strings:
    $key_ea44 = { b9 2b [2] 9d 25 [2] b6 09 [2] 98 2b [2] 8c 30 [2] 83 2a [2] 9d 37 [2] 9f 36 [2] 84 30 [2] 98 37 [2] 84 18 }

  condition:
    any of them
}