rule TTP_XOR_QUAD_CurrentVersionRun_5eed {
  strings:
    $key_5eed = { 0d 82 [2] 29 8c [2] 02 a0 [2] 2c 82 [2] 38 99 [2] 37 83 [2] 29 9e [2] 2b 9f [2] 30 99 [2] 2c 9e [2] 30 b1 }

  condition:
    any of them
}