rule TTP_XOR_QUAD_CurrentVersionRun_5a40 {
  strings:
    $key_5a40 = { 09 2f [2] 2d 21 [2] 06 0d [2] 28 2f [2] 3c 34 [2] 33 2e [2] 2d 33 [2] 2f 32 [2] 34 34 [2] 28 33 [2] 34 1c }

  condition:
    any of them
}