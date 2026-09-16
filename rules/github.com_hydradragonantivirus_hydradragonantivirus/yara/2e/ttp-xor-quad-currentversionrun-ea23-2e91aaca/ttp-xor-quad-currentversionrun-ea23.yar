rule TTP_XOR_QUAD_CurrentVersionRun_ea23 {
  strings:
    $key_ea23 = { b9 4c [2] 9d 42 [2] b6 6e [2] 98 4c [2] 8c 57 [2] 83 4d [2] 9d 50 [2] 9f 51 [2] 84 57 [2] 98 50 [2] 84 7f }

  condition:
    any of them
}