rule TTP_XOR_QUAD_CurrentVersionRun_4e40 {
  strings:
    $key_4e40 = { 1d 2f [2] 39 21 [2] 12 0d [2] 3c 2f [2] 28 34 [2] 27 2e [2] 39 33 [2] 3b 32 [2] 20 34 [2] 3c 33 [2] 20 1c }

  condition:
    any of them
}