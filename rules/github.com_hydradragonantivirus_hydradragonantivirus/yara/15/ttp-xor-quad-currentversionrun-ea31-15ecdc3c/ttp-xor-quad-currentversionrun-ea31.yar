rule TTP_XOR_QUAD_CurrentVersionRun_ea31 {
  strings:
    $key_ea31 = { b9 5e [2] 9d 50 [2] b6 7c [2] 98 5e [2] 8c 45 [2] 83 5f [2] 9d 42 [2] 9f 43 [2] 84 45 [2] 98 42 [2] 84 6d }

  condition:
    any of them
}