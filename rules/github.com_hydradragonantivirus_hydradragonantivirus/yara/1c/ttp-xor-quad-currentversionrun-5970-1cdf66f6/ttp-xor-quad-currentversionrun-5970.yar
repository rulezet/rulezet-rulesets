rule TTP_XOR_QUAD_CurrentVersionRun_5970 {
  strings:
    $key_5970 = { 0a 1f [2] 2e 11 [2] 05 3d [2] 2b 1f [2] 3f 04 [2] 30 1e [2] 2e 03 [2] 2c 02 [2] 37 04 [2] 2b 03 [2] 37 2c }

  condition:
    any of them
}