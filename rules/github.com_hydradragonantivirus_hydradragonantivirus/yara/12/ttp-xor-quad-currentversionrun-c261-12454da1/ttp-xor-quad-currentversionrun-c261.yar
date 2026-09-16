rule TTP_XOR_QUAD_CurrentVersionRun_c261 {
  strings:
    $key_c261 = { 91 0e [2] b5 00 [2] 9e 2c [2] b0 0e [2] a4 15 [2] ab 0f [2] b5 12 [2] b7 13 [2] ac 15 [2] b0 12 [2] ac 3d }

  condition:
    any of them
}