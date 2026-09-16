rule TTP_XOR_QUAD_CurrentVersionRun_7010 {
  strings:
    $key_7010 = { 23 7f [2] 07 71 [2] 2c 5d [2] 02 7f [2] 16 64 [2] 19 7e [2] 07 63 [2] 05 62 [2] 1e 64 [2] 02 63 [2] 1e 4c }

  condition:
    any of them
}