rule TTP_XOR_QUAD_CurrentVersionRun_6910 {
  strings:
    $key_6910 = { 3a 7f [2] 1e 71 [2] 35 5d [2] 1b 7f [2] 0f 64 [2] 00 7e [2] 1e 63 [2] 1c 62 [2] 07 64 [2] 1b 63 [2] 07 4c }

  condition:
    any of them
}