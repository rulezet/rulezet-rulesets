rule TTP_XOR_QUAD_CurrentVersionRun_ea50 {
  strings:
    $key_ea50 = { b9 3f [2] 9d 31 [2] b6 1d [2] 98 3f [2] 8c 24 [2] 83 3e [2] 9d 23 [2] 9f 22 [2] 84 24 [2] 98 23 [2] 84 0c }

  condition:
    any of them
}