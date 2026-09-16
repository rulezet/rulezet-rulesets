rule TTP_XOR_QUAD_CurrentVersionRun_4570 {
  strings:
    $key_4570 = { 16 1f [2] 32 11 [2] 19 3d [2] 37 1f [2] 23 04 [2] 2c 1e [2] 32 03 [2] 30 02 [2] 2b 04 [2] 37 03 [2] 2b 2c }

  condition:
    any of them
}