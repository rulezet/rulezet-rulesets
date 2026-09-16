rule TTP_XOR_QUAD_CurrentVersionRun_6710 {
  strings:
    $key_6710 = { 34 7f [2] 10 71 [2] 3b 5d [2] 15 7f [2] 01 64 [2] 0e 7e [2] 10 63 [2] 12 62 [2] 09 64 [2] 15 63 [2] 09 4c }

  condition:
    any of them
}