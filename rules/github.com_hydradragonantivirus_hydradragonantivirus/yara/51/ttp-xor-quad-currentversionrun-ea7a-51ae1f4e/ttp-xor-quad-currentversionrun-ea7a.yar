rule TTP_XOR_QUAD_CurrentVersionRun_ea7a {
  strings:
    $key_ea7a = { b9 15 [2] 9d 1b [2] b6 37 [2] 98 15 [2] 8c 0e [2] 83 14 [2] 9d 09 [2] 9f 08 [2] 84 0e [2] 98 09 [2] 84 26 }

  condition:
    any of them
}