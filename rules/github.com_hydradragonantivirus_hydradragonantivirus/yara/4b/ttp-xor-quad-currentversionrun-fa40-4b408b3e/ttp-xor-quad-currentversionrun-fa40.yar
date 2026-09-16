rule TTP_XOR_QUAD_CurrentVersionRun_fa40 {
  strings:
    $key_fa40 = { a9 2f [2] 8d 21 [2] a6 0d [2] 88 2f [2] 9c 34 [2] 93 2e [2] 8d 33 [2] 8f 32 [2] 94 34 [2] 88 33 [2] 94 1c }

  condition:
    any of them
}