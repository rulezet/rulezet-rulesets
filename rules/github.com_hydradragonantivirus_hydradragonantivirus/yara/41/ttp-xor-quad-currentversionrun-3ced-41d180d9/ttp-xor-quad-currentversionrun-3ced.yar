rule TTP_XOR_QUAD_CurrentVersionRun_3ced {
  strings:
    $key_3ced = { 6f 82 [2] 4b 8c [2] 60 a0 [2] 4e 82 [2] 5a 99 [2] 55 83 [2] 4b 9e [2] 49 9f [2] 52 99 [2] 4e 9e [2] 52 b1 }

  condition:
    any of them
}