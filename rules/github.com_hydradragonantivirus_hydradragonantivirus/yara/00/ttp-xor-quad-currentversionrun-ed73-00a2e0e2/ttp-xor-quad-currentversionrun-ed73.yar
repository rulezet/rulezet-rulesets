rule TTP_XOR_QUAD_CurrentVersionRun_ed73 {
  strings:
    $key_ed73 = { be 1c [2] 9a 12 [2] b1 3e [2] 9f 1c [2] 8b 07 [2] 84 1d [2] 9a 00 [2] 98 01 [2] 83 07 [2] 9f 00 [2] 83 2f }

  condition:
    any of them
}