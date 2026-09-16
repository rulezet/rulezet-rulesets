rule TTP_XOR_QUAD_CurrentVersionRun_732c {
  strings:
    $key_732c = { 20 43 [2] 04 4d [2] 2f 61 [2] 01 43 [2] 15 58 [2] 1a 42 [2] 04 5f [2] 06 5e [2] 1d 58 [2] 01 5f [2] 1d 70 }

  condition:
    any of them
}