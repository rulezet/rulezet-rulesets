rule TTP_XOR_QUAD_CurrentVersionRun_ea39 {
  strings:
    $key_ea39 = { b9 56 [2] 9d 58 [2] b6 74 [2] 98 56 [2] 8c 4d [2] 83 57 [2] 9d 4a [2] 9f 4b [2] 84 4d [2] 98 4a [2] 84 65 }

  condition:
    any of them
}