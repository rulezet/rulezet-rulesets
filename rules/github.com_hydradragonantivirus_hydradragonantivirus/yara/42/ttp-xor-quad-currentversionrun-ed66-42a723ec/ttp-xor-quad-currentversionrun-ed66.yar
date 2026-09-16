rule TTP_XOR_QUAD_CurrentVersionRun_ed66 {
  strings:
    $key_ed66 = { be 09 [2] 9a 07 [2] b1 2b [2] 9f 09 [2] 8b 12 [2] 84 08 [2] 9a 15 [2] 98 14 [2] 83 12 [2] 9f 15 [2] 83 3a }

  condition:
    any of them
}