rule TTP_XOR_QUAD_CurrentVersionRun_5050 {
  strings:
    $key_5050 = { 03 3f [2] 27 31 [2] 0c 1d [2] 22 3f [2] 36 24 [2] 39 3e [2] 27 23 [2] 25 22 [2] 3e 24 [2] 22 23 [2] 3e 0c }

  condition:
    any of them
}