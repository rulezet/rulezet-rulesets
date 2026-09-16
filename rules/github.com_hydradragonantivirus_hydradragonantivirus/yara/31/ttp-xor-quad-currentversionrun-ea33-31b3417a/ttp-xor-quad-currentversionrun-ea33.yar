rule TTP_XOR_QUAD_CurrentVersionRun_ea33 {
  strings:
    $key_ea33 = { b9 5c [2] 9d 52 [2] b6 7e [2] 98 5c [2] 8c 47 [2] 83 5d [2] 9d 40 [2] 9f 41 [2] 84 47 [2] 98 40 [2] 84 6f }

  condition:
    any of them
}