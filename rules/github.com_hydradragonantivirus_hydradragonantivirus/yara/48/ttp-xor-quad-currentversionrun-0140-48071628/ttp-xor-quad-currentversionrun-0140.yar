rule TTP_XOR_QUAD_CurrentVersionRun_0140 {
  strings:
    $key_0140 = { 52 2f [2] 76 21 [2] 5d 0d [2] 73 2f [2] 67 34 [2] 68 2e [2] 76 33 [2] 74 32 [2] 6f 34 [2] 73 33 [2] 6f 1c }

  condition:
    any of them
}