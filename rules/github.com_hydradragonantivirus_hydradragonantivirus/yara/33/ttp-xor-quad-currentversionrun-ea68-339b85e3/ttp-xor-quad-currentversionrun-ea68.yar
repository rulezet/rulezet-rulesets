rule TTP_XOR_QUAD_CurrentVersionRun_ea68 {
  strings:
    $key_ea68 = { b9 07 [2] 9d 09 [2] b6 25 [2] 98 07 [2] 8c 1c [2] 83 06 [2] 9d 1b [2] 9f 1a [2] 84 1c [2] 98 1b [2] 84 34 }

  condition:
    any of them
}