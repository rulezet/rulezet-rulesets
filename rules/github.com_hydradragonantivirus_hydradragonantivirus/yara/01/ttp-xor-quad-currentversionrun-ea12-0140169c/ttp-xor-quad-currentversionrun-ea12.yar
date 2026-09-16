rule TTP_XOR_QUAD_CurrentVersionRun_ea12 {
  strings:
    $key_ea12 = { b9 7d [2] 9d 73 [2] b6 5f [2] 98 7d [2] 8c 66 [2] 83 7c [2] 9d 61 [2] 9f 60 [2] 84 66 [2] 98 61 [2] 84 4e }

  condition:
    any of them
}