rule TTP_XOR_QUAD_CurrentVersionRun_ed25 {
  strings:
    $key_ed25 = { be 4a [2] 9a 44 [2] b1 68 [2] 9f 4a [2] 8b 51 [2] 84 4b [2] 9a 56 [2] 98 57 [2] 83 51 [2] 9f 56 [2] 83 79 }

  condition:
    any of them
}