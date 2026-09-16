rule TTP_XOR_QUAD_CurrentVersionRun_587c {
  strings:
    $key_587c = { 0b 13 [2] 2f 1d [2] 04 31 [2] 2a 13 [2] 3e 08 [2] 31 12 [2] 2f 0f [2] 2d 0e [2] 36 08 [2] 2a 0f [2] 36 20 }

  condition:
    any of them
}