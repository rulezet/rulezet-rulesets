rule TTP_XOR_QUAD_CurrentVersionRun_4ced {
  strings:
    $key_4ced = { 1f 82 [2] 3b 8c [2] 10 a0 [2] 3e 82 [2] 2a 99 [2] 25 83 [2] 3b 9e [2] 39 9f [2] 22 99 [2] 3e 9e [2] 22 b1 }

  condition:
    any of them
}