rule TTP_XOR_QUAD_CurrentVersionRun_7eed {
  strings:
    $key_7eed = { 2d 82 [2] 09 8c [2] 22 a0 [2] 0c 82 [2] 18 99 [2] 17 83 [2] 09 9e [2] 0b 9f [2] 10 99 [2] 0c 9e [2] 10 b1 }

  condition:
    any of them
}