rule TTP_XOR_QUAD_CurrentVersionRun_4970 {
  strings:
    $key_4970 = { 1a 1f [2] 3e 11 [2] 15 3d [2] 3b 1f [2] 2f 04 [2] 20 1e [2] 3e 03 [2] 3c 02 [2] 27 04 [2] 3b 03 [2] 27 2c }

  condition:
    any of them
}