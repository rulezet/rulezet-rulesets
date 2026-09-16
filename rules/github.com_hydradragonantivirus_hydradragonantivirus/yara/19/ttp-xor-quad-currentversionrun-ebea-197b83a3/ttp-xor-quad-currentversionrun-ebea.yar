rule TTP_XOR_QUAD_CurrentVersionRun_ebea {
  strings:
    $key_ebea = { b8 85 [2] 9c 8b [2] b7 a7 [2] 99 85 [2] 8d 9e [2] 82 84 [2] 9c 99 [2] 9e 98 [2] 85 9e [2] 99 99 [2] 85 b6 }

  condition:
    any of them
}