rule TTP_XOR_QUAD_CurrentVersionRun_4050 {
  strings:
    $key_4050 = { 13 3f [2] 37 31 [2] 1c 1d [2] 32 3f [2] 26 24 [2] 29 3e [2] 37 23 [2] 35 22 [2] 2e 24 [2] 32 23 [2] 2e 0c }

  condition:
    any of them
}