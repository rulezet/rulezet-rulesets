rule TTP_XOR_QUAD_CurrentVersionRun_1c50 {
  strings:
    $key_1c50 = { 4f 3f [2] 6b 31 [2] 40 1d [2] 6e 3f [2] 7a 24 [2] 75 3e [2] 6b 23 [2] 69 22 [2] 72 24 [2] 6e 23 [2] 72 0c }

  condition:
    any of them
}