rule TTP_XOR_QUAD_CurrentVersionRun_5210 {
  strings:
    $key_5210 = { 01 7f [2] 25 71 [2] 0e 5d [2] 20 7f [2] 34 64 [2] 3b 7e [2] 25 63 [2] 27 62 [2] 3c 64 [2] 20 63 [2] 3c 4c }

  condition:
    any of them
}