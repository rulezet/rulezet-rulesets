rule TTP_XOR_QUAD_CurrentVersionRun_7fed {
  strings:
    $key_7fed = { 2c 82 [2] 08 8c [2] 23 a0 [2] 0d 82 [2] 19 99 [2] 16 83 [2] 08 9e [2] 0a 9f [2] 11 99 [2] 0d 9e [2] 11 b1 }

  condition:
    any of them
}