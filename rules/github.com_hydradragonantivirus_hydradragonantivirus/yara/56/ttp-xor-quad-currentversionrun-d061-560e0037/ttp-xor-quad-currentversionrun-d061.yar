rule TTP_XOR_QUAD_CurrentVersionRun_d061 {
  strings:
    $key_d061 = { 83 0e [2] a7 00 [2] 8c 2c [2] a2 0e [2] b6 15 [2] b9 0f [2] a7 12 [2] a5 13 [2] be 15 [2] a2 12 [2] be 3d }

  condition:
    any of them
}