rule TTP_XOR_QUAD_CurrentVersionRun_ed4a {
  strings:
    $key_ed4a = { be 25 [2] 9a 2b [2] b1 07 [2] 9f 25 [2] 8b 3e [2] 84 24 [2] 9a 39 [2] 98 38 [2] 83 3e [2] 9f 39 [2] 83 16 }

  condition:
    any of them
}