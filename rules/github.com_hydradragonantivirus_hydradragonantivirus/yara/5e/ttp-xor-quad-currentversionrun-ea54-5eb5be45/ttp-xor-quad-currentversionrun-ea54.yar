rule TTP_XOR_QUAD_CurrentVersionRun_ea54 {
  strings:
    $key_ea54 = { b9 3b [2] 9d 35 [2] b6 19 [2] 98 3b [2] 8c 20 [2] 83 3a [2] 9d 27 [2] 9f 26 [2] 84 20 [2] 98 27 [2] 84 08 }

  condition:
    any of them
}