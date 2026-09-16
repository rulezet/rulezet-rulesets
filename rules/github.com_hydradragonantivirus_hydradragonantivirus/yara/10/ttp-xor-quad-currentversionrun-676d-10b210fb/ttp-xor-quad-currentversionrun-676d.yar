rule TTP_XOR_QUAD_CurrentVersionRun_676d {
  strings:
    $key_676d = { 34 02 [2] 10 0c [2] 3b 20 [2] 15 02 [2] 01 19 [2] 0e 03 [2] 10 1e [2] 12 1f [2] 09 19 [2] 15 1e [2] 09 31 }

  condition:
    any of them
}