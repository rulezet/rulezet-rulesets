rule TTP_XOR_QUAD_CurrentVersionRun_2050 {
  strings:
    $key_2050 = { 73 3f [2] 57 31 [2] 7c 1d [2] 52 3f [2] 46 24 [2] 49 3e [2] 57 23 [2] 55 22 [2] 4e 24 [2] 52 23 [2] 4e 0c }

  condition:
    any of them
}