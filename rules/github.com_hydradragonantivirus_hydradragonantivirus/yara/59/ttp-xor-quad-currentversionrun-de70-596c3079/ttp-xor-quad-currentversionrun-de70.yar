rule TTP_XOR_QUAD_CurrentVersionRun_de70 {
  strings:
    $key_de70 = { 8d 1f [2] a9 11 [2] 82 3d [2] ac 1f [2] b8 04 [2] b7 1e [2] a9 03 [2] ab 02 [2] b0 04 [2] ac 03 [2] b0 2c }

  condition:
    any of them
}