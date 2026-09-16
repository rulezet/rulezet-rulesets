rule TTP_XOR_QUAD_CurrentVersionRun_de61 {
  strings:
    $key_de61 = { 8d 0e [2] a9 00 [2] 82 2c [2] ac 0e [2] b8 15 [2] b7 0f [2] a9 12 [2] ab 13 [2] b0 15 [2] ac 12 [2] b0 3d }

  condition:
    any of them
}