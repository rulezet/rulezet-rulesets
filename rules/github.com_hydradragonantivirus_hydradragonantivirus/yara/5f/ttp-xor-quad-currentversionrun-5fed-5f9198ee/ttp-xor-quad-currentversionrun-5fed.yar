rule TTP_XOR_QUAD_CurrentVersionRun_5fed {
  strings:
    $key_5fed = { 0c 82 [2] 28 8c [2] 03 a0 [2] 2d 82 [2] 39 99 [2] 36 83 [2] 28 9e [2] 2a 9f [2] 31 99 [2] 2d 9e [2] 31 b1 }

  condition:
    any of them
}