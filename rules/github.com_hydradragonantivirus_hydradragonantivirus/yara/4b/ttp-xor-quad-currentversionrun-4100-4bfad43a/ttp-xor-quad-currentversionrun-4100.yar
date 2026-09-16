rule TTP_XOR_QUAD_CurrentVersionRun_4100 {
  strings:
    $key_4100 = { 12 6f [2] 36 61 [2] 1d 4d [2] 33 6f [2] 27 74 [2] 28 6e [2] 36 73 [2] 34 72 [2] 2f 74 [2] 33 73 [2] 2f 5c }

  condition:
    any of them
}