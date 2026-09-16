rule TTP_XOR_QUAD_CurrentVersionRun_7240 {
  strings:
    $key_7240 = { 21 2f [2] 05 21 [2] 2e 0d [2] 00 2f [2] 14 34 [2] 1b 2e [2] 05 33 [2] 07 32 [2] 1c 34 [2] 00 33 [2] 1c 1c }

  condition:
    any of them
}