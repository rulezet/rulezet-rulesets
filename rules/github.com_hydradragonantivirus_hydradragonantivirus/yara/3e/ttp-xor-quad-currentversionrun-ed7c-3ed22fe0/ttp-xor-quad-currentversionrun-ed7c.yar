rule TTP_XOR_QUAD_CurrentVersionRun_ed7c {
  strings:
    $key_ed7c = { be 13 [2] 9a 1d [2] b1 31 [2] 9f 13 [2] 8b 08 [2] 84 12 [2] 9a 0f [2] 98 0e [2] 83 08 [2] 9f 0f [2] 83 20 }

  condition:
    any of them
}