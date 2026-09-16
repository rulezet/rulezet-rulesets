rule TTP_XOR_QUAD_CurrentVersionRun_7950 {
  strings:
    $key_7950 = { 2a 3f [2] 0e 31 [2] 25 1d [2] 0b 3f [2] 1f 24 [2] 10 3e [2] 0e 23 [2] 0c 22 [2] 17 24 [2] 0b 23 [2] 17 0c }

  condition:
    any of them
}