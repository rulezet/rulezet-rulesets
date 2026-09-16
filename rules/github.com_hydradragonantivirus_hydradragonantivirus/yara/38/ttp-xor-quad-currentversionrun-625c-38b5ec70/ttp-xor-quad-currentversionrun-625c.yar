rule TTP_XOR_QUAD_CurrentVersionRun_625c {
  strings:
    $key_625c = { 31 33 [2] 15 3d [2] 3e 11 [2] 10 33 [2] 04 28 [2] 0b 32 [2] 15 2f [2] 17 2e [2] 0c 28 [2] 10 2f [2] 0c 00 }

  condition:
    any of them
}