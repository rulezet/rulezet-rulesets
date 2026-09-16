rule TTP_XOR_QUAD_CurrentVersionRun_ea72 {
  strings:
    $key_ea72 = { b9 1d [2] 9d 13 [2] b6 3f [2] 98 1d [2] 8c 06 [2] 83 1c [2] 9d 01 [2] 9f 00 [2] 84 06 [2] 98 01 [2] 84 2e }

  condition:
    any of them
}