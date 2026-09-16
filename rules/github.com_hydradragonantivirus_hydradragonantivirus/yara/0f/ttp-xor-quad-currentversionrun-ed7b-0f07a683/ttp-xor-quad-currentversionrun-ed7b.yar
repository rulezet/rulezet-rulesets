rule TTP_XOR_QUAD_CurrentVersionRun_ed7b {
  strings:
    $key_ed7b = { be 14 [2] 9a 1a [2] b1 36 [2] 9f 14 [2] 8b 0f [2] 84 15 [2] 9a 08 [2] 98 09 [2] 83 0f [2] 9f 08 [2] 83 27 }

  condition:
    any of them
}