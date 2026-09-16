rule TTP_XOR_QUAD_CurrentVersionRun_ea79 {
  strings:
    $key_ea79 = { b9 16 [2] 9d 18 [2] b6 34 [2] 98 16 [2] 8c 0d [2] 83 17 [2] 9d 0a [2] 9f 0b [2] 84 0d [2] 98 0a [2] 84 25 }

  condition:
    any of them
}