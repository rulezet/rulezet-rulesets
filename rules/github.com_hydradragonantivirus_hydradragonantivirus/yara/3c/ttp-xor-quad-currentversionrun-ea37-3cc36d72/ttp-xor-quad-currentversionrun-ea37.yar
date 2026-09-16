rule TTP_XOR_QUAD_CurrentVersionRun_ea37 {
  strings:
    $key_ea37 = { b9 58 [2] 9d 56 [2] b6 7a [2] 98 58 [2] 8c 43 [2] 83 59 [2] 9d 44 [2] 9f 45 [2] 84 43 [2] 98 44 [2] 84 6b }

  condition:
    any of them
}