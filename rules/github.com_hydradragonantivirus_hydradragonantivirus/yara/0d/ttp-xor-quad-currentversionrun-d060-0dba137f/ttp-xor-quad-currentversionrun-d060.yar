rule TTP_XOR_QUAD_CurrentVersionRun_d060 {
  strings:
    $key_d060 = { 83 0f [2] a7 01 [2] 8c 2d [2] a2 0f [2] b6 14 [2] b9 0e [2] a7 13 [2] a5 12 [2] be 14 [2] a2 13 [2] be 3c }

  condition:
    any of them
}