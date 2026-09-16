rule TTP_XOR_QUAD_CurrentVersionRun_ea32 {
  strings:
    $key_ea32 = { b9 5d [2] 9d 53 [2] b6 7f [2] 98 5d [2] 8c 46 [2] 83 5c [2] 9d 41 [2] 9f 40 [2] 84 46 [2] 98 41 [2] 84 6e }

  condition:
    any of them
}