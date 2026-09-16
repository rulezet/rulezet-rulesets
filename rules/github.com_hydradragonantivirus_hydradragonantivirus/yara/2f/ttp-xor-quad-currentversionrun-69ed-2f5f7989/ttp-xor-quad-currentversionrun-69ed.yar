rule TTP_XOR_QUAD_CurrentVersionRun_69ed {
  strings:
    $key_69ed = { 3a 82 [2] 1e 8c [2] 35 a0 [2] 1b 82 [2] 0f 99 [2] 00 83 [2] 1e 9e [2] 1c 9f [2] 07 99 [2] 1b 9e [2] 07 b1 }

  condition:
    any of them
}