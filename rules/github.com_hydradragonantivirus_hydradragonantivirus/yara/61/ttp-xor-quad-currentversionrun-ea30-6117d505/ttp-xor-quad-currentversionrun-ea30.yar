rule TTP_XOR_QUAD_CurrentVersionRun_ea30 {
  strings:
    $key_ea30 = { b9 5f [2] 9d 51 [2] b6 7d [2] 98 5f [2] 8c 44 [2] 83 5e [2] 9d 43 [2] 9f 42 [2] 84 44 [2] 98 43 [2] 84 6c }

  condition:
    any of them
}