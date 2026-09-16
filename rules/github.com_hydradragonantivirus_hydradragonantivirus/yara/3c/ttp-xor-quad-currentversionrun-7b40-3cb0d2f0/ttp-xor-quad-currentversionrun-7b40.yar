rule TTP_XOR_QUAD_CurrentVersionRun_7b40 {
  strings:
    $key_7b40 = { 28 2f [2] 0c 21 [2] 27 0d [2] 09 2f [2] 1d 34 [2] 12 2e [2] 0c 33 [2] 0e 32 [2] 15 34 [2] 09 33 [2] 15 1c }

  condition:
    any of them
}