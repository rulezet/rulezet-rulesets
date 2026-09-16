rule TTP_XOR_QUAD_CurrentVersionRun_4950 {
  strings:
    $key_4950 = { 1a 3f [2] 3e 31 [2] 15 1d [2] 3b 3f [2] 2f 24 [2] 20 3e [2] 3e 23 [2] 3c 22 [2] 27 24 [2] 3b 23 [2] 27 0c }

  condition:
    any of them
}