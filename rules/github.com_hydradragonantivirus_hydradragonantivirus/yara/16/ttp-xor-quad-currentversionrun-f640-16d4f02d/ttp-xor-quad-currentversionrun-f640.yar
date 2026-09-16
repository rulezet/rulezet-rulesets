rule TTP_XOR_QUAD_CurrentVersionRun_f640 {
  strings:
    $key_f640 = { a5 2f [2] 81 21 [2] aa 0d [2] 84 2f [2] 90 34 [2] 9f 2e [2] 81 33 [2] 83 32 [2] 98 34 [2] 84 33 [2] 98 1c }

  condition:
    any of them
}