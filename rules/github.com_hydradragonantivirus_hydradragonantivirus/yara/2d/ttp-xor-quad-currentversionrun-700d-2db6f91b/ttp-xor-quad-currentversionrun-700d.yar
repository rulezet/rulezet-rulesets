rule TTP_XOR_QUAD_CurrentVersionRun_700d {
  strings:
    $key_700d = { 23 62 [2] 07 6c [2] 2c 40 [2] 02 62 [2] 16 79 [2] 19 63 [2] 07 7e [2] 05 7f [2] 1e 79 [2] 02 7e [2] 1e 51 }

  condition:
    any of them
}