rule TTP_XOR_QUAD_CurrentVersionRun_ed67 {
  strings:
    $key_ed67 = { be 08 [2] 9a 06 [2] b1 2a [2] 9f 08 [2] 8b 13 [2] 84 09 [2] 9a 14 [2] 98 15 [2] 83 13 [2] 9f 14 [2] 83 3b }

  condition:
    any of them
}