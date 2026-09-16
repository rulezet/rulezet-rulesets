rule TTP_XOR_QUAD_CurrentVersionRun_67fc {
  strings:
    $key_67fc = { 34 93 [2] 10 9d [2] 3b b1 [2] 15 93 [2] 01 88 [2] 0e 92 [2] 10 8f [2] 12 8e [2] 09 88 [2] 15 8f [2] 09 a0 }

  condition:
    any of them
}