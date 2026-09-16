rule TTP_XOR_QUAD_CurrentVersionRun_ed7d {
  strings:
    $key_ed7d = { be 12 [2] 9a 1c [2] b1 30 [2] 9f 12 [2] 8b 09 [2] 84 13 [2] 9a 0e [2] 98 0f [2] 83 09 [2] 9f 0e [2] 83 21 }

  condition:
    any of them
}