rule TTP_XOR_QUAD_CurrentVersionRun_ea45 {
  strings:
    $key_ea45 = { b9 2a [2] 9d 24 [2] b6 08 [2] 98 2a [2] 8c 31 [2] 83 2b [2] 9d 36 [2] 9f 37 [2] 84 31 [2] 98 36 [2] 84 19 }

  condition:
    any of them
}