rule TTP_XOR_QUAD_CurrentVersionRun_5510 {
  strings:
    $key_5510 = { 06 7f [2] 22 71 [2] 09 5d [2] 27 7f [2] 33 64 [2] 3c 7e [2] 22 63 [2] 20 62 [2] 3b 64 [2] 27 63 [2] 3b 4c }

  condition:
    any of them
}