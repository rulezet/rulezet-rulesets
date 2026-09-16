rule TTP_XOR_QUAD_CurrentVersionRun_ed68 {
  strings:
    $key_ed68 = { be 07 [2] 9a 09 [2] b1 25 [2] 9f 07 [2] 8b 1c [2] 84 06 [2] 9a 1b [2] 98 1a [2] 83 1c [2] 9f 1b [2] 83 34 }

  condition:
    any of them
}