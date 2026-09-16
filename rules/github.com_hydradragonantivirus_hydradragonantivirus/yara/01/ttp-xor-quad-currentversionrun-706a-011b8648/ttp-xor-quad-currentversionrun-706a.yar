rule TTP_XOR_QUAD_CurrentVersionRun_706a {
  strings:
    $key_706a = { 23 05 [2] 07 0b [2] 2c 27 [2] 02 05 [2] 16 1e [2] 19 04 [2] 07 19 [2] 05 18 [2] 1e 1e [2] 02 19 [2] 1e 36 }

  condition:
    any of them
}