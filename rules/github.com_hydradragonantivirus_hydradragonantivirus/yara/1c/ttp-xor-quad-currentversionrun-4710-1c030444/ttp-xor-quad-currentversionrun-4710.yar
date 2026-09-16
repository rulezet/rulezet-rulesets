rule TTP_XOR_QUAD_CurrentVersionRun_4710 {
  strings:
    $key_4710 = { 14 7f [2] 30 71 [2] 1b 5d [2] 35 7f [2] 21 64 [2] 2e 7e [2] 30 63 [2] 32 62 [2] 29 64 [2] 35 63 [2] 29 4c }

  condition:
    any of them
}