rule TTP_XOR_QUAD_CurrentVersionRun_0ced {
  strings:
    $key_0ced = { 5f 82 [2] 7b 8c [2] 50 a0 [2] 7e 82 [2] 6a 99 [2] 65 83 [2] 7b 9e [2] 79 9f [2] 62 99 [2] 7e 9e [2] 62 b1 }

  condition:
    any of them
}