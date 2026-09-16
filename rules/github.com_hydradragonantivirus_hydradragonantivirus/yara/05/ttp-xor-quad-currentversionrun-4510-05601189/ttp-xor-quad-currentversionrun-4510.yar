rule TTP_XOR_QUAD_CurrentVersionRun_4510 {
  strings:
    $key_4510 = { 16 7f [2] 32 71 [2] 19 5d [2] 37 7f [2] 23 64 [2] 2c 7e [2] 32 63 [2] 30 62 [2] 2b 64 [2] 37 63 [2] 2b 4c }

  condition:
    any of them
}