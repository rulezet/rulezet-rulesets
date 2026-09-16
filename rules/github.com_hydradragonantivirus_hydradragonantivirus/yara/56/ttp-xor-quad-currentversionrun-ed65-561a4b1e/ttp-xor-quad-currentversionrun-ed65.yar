rule TTP_XOR_QUAD_CurrentVersionRun_ed65 {
  strings:
    $key_ed65 = { be 0a [2] 9a 04 [2] b1 28 [2] 9f 0a [2] 8b 11 [2] 84 0b [2] 9a 16 [2] 98 17 [2] 83 11 [2] 9f 16 [2] 83 39 }

  condition:
    any of them
}