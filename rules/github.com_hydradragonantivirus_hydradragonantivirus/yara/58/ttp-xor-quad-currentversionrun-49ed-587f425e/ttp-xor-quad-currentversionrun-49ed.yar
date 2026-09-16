rule TTP_XOR_QUAD_CurrentVersionRun_49ed {
  strings:
    $key_49ed = { 1a 82 [2] 3e 8c [2] 15 a0 [2] 3b 82 [2] 2f 99 [2] 20 83 [2] 3e 9e [2] 3c 9f [2] 27 99 [2] 3b 9e [2] 27 b1 }

  condition:
    any of them
}