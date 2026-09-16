rule TTP_XOR_QUAD_CurrentVersionRun_ea6b {
  strings:
    $key_ea6b = { b9 04 [2] 9d 0a [2] b6 26 [2] 98 04 [2] 8c 1f [2] 83 05 [2] 9d 18 [2] 9f 19 [2] 84 1f [2] 98 18 [2] 84 37 }

  condition:
    any of them
}