rule TTP_XOR_QUAD_CurrentVersionRun_676c {
  strings:
    $key_676c = { 34 03 [2] 10 0d [2] 3b 21 [2] 15 03 [2] 01 18 [2] 0e 02 [2] 10 1f [2] 12 1e [2] 09 18 [2] 15 1f [2] 09 30 }

  condition:
    any of them
}