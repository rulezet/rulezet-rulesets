rule TTP_XOR_QUAD_CurrentVersionRun_7430 {
  strings:
    $key_7430 = { 27 5f [2] 03 51 [2] 28 7d [2] 06 5f [2] 12 44 [2] 1d 5e [2] 03 43 [2] 01 42 [2] 1a 44 [2] 06 43 [2] 1a 6c }

  condition:
    any of them
}