rule TTP_XOR_QUAD_CurrentVersionRun_ea21 {
  strings:
    $key_ea21 = { b9 4e [2] 9d 40 [2] b6 6c [2] 98 4e [2] 8c 55 [2] 83 4f [2] 9d 52 [2] 9f 53 [2] 84 55 [2] 98 52 [2] 84 7d }

  condition:
    any of them
}