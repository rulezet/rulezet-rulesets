rule TTP_XOR_QUAD_CurrentVersionRun_ea02 {
  strings:
    $key_ea02 = { b9 6d [2] 9d 63 [2] b6 4f [2] 98 6d [2] 8c 76 [2] 83 6c [2] 9d 71 [2] 9f 70 [2] 84 76 [2] 98 71 [2] 84 5e }

  condition:
    any of them
}