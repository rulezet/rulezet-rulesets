rule TTP_XOR_QUAD_CurrentVersionRun_ea7c {
  strings:
    $key_ea7c = { b9 13 [2] 9d 1d [2] b6 31 [2] 98 13 [2] 8c 08 [2] 83 12 [2] 9d 0f [2] 9f 0e [2] 84 08 [2] 98 0f [2] 84 20 }

  condition:
    any of them
}