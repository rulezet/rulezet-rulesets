rule TTP_XOR_QUAD_CurrentVersionRun_e570 {
  strings:
    $key_e570 = { b6 1f [2] 92 11 [2] b9 3d [2] 97 1f [2] 83 04 [2] 8c 1e [2] 92 03 [2] 90 02 [2] 8b 04 [2] 97 03 [2] 8b 2c }

  condition:
    any of them
}