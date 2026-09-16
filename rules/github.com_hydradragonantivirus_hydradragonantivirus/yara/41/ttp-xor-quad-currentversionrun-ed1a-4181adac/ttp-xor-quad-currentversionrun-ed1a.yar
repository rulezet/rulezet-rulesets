rule TTP_XOR_QUAD_CurrentVersionRun_ed1a {
  strings:
    $key_ed1a = { be 75 [2] 9a 7b [2] b1 57 [2] 9f 75 [2] 8b 6e [2] 84 74 [2] 9a 69 [2] 98 68 [2] 83 6e [2] 9f 69 [2] 83 46 }

  condition:
    any of them
}