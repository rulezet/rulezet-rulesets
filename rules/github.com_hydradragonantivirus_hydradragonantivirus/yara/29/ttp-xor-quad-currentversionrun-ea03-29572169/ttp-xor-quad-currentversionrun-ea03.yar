rule TTP_XOR_QUAD_CurrentVersionRun_ea03 {
  strings:
    $key_ea03 = { b9 6c [2] 9d 62 [2] b6 4e [2] 98 6c [2] 8c 77 [2] 83 6d [2] 9d 70 [2] 9f 71 [2] 84 77 [2] 98 70 [2] 84 5f }

  condition:
    any of them
}