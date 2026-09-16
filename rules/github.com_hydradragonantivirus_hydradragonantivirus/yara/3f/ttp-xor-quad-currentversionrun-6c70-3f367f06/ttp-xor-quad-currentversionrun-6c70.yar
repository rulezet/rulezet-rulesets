rule TTP_XOR_QUAD_CurrentVersionRun_6c70 {
  strings:
    $key_6c70 = { 3f 1f [2] 1b 11 [2] 30 3d [2] 1e 1f [2] 0a 04 [2] 05 1e [2] 1b 03 [2] 19 02 [2] 02 04 [2] 1e 03 [2] 02 2c }

  condition:
    any of them
}