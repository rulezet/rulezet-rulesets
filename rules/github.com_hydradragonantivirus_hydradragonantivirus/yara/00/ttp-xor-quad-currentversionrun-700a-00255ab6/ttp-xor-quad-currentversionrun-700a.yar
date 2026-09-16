rule TTP_XOR_QUAD_CurrentVersionRun_700a {
  strings:
    $key_700a = { 23 65 [2] 07 6b [2] 2c 47 [2] 02 65 [2] 16 7e [2] 19 64 [2] 07 79 [2] 05 78 [2] 1e 7e [2] 02 79 [2] 1e 56 }

  condition:
    any of them
}