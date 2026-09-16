rule TTP_XOR_QUAD_CurrentVersionRun_ea22 {
  strings:
    $key_ea22 = { b9 4d [2] 9d 43 [2] b6 6f [2] 98 4d [2] 8c 56 [2] 83 4c [2] 9d 51 [2] 9f 50 [2] 84 56 [2] 98 51 [2] 84 7e }

  condition:
    any of them
}