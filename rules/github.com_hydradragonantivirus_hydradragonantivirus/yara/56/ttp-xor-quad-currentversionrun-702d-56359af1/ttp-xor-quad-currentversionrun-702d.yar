rule TTP_XOR_QUAD_CurrentVersionRun_702d {
  strings:
    $key_702d = { 23 42 [2] 07 4c [2] 2c 60 [2] 02 42 [2] 16 59 [2] 19 43 [2] 07 5e [2] 05 5f [2] 1e 59 [2] 02 5e [2] 1e 71 }

  condition:
    any of them
}