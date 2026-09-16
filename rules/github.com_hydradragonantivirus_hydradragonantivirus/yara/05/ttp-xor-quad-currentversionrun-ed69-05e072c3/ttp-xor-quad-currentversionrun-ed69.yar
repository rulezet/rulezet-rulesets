rule TTP_XOR_QUAD_CurrentVersionRun_ed69 {
  strings:
    $key_ed69 = { be 06 [2] 9a 08 [2] b1 24 [2] 9f 06 [2] 8b 1d [2] 84 07 [2] 9a 1a [2] 98 1b [2] 83 1d [2] 9f 1a [2] 83 35 }

  condition:
    any of them
}