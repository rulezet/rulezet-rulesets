rule TTP_XOR_QUAD_CurrentVersionRun_2140 {
  strings:
    $key_2140 = { 72 2f [2] 56 21 [2] 7d 0d [2] 53 2f [2] 47 34 [2] 48 2e [2] 56 33 [2] 54 32 [2] 4f 34 [2] 53 33 [2] 4f 1c }

  condition:
    any of them
}