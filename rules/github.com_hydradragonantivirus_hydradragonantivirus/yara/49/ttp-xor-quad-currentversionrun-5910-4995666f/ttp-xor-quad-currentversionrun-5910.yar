rule TTP_XOR_QUAD_CurrentVersionRun_5910 {
  strings:
    $key_5910 = { 0a 7f [2] 2e 71 [2] 05 5d [2] 2b 7f [2] 3f 64 [2] 30 7e [2] 2e 63 [2] 2c 62 [2] 37 64 [2] 2b 63 [2] 37 4c }

  condition:
    any of them
}