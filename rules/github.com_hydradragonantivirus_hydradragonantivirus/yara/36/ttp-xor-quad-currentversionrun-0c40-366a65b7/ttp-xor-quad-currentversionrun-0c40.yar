rule TTP_XOR_QUAD_CurrentVersionRun_0c40 {
  strings:
    $key_0c40 = { 5f 2f [2] 7b 21 [2] 50 0d [2] 7e 2f [2] 6a 34 [2] 65 2e [2] 7b 33 [2] 79 32 [2] 62 34 [2] 7e 33 [2] 62 1c }

  condition:
    any of them
}