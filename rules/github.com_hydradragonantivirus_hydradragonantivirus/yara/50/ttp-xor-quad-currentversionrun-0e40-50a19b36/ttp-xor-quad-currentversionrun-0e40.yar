rule TTP_XOR_QUAD_CurrentVersionRun_0e40 {
  strings:
    $key_0e40 = { 5d 2f [2] 79 21 [2] 52 0d [2] 7c 2f [2] 68 34 [2] 67 2e [2] 79 33 [2] 7b 32 [2] 60 34 [2] 7c 33 [2] 60 1c }

  condition:
    any of them
}