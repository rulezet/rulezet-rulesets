rule TTP_XOR_QUAD_CurrentVersionRun_5550 {
  strings:
    $key_5550 = { 06 3f [2] 22 31 [2] 09 1d [2] 27 3f [2] 33 24 [2] 3c 3e [2] 22 23 [2] 20 22 [2] 3b 24 [2] 27 23 [2] 3b 0c }

  condition:
    any of them
}