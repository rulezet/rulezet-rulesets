rule TTP_XOR_QUAD_CurrentVersionRun_2ced {
  strings:
    $key_2ced = { 7f 82 [2] 5b 8c [2] 70 a0 [2] 5e 82 [2] 4a 99 [2] 45 83 [2] 5b 9e [2] 59 9f [2] 42 99 [2] 5e 9e [2] 42 b1 }

  condition:
    any of them
}