rule TTP_XOR_QUAD_CurrentVersionRun_e970 {
  strings:
    $key_e970 = { ba 1f [2] 9e 11 [2] b5 3d [2] 9b 1f [2] 8f 04 [2] 80 1e [2] 9e 03 [2] 9c 02 [2] 87 04 [2] 9b 03 [2] 87 2c }

  condition:
    any of them
}