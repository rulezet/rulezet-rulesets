rule TTP_XOR_QUAD_CurrentVersionRun_6550 {
  strings:
    $key_6550 = { 36 3f [2] 12 31 [2] 39 1d [2] 17 3f [2] 03 24 [2] 0c 3e [2] 12 23 [2] 10 22 [2] 0b 24 [2] 17 23 [2] 0b 0c }

  condition:
    any of them
}