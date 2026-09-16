rule TTP_XOR_QUAD_CurrentVersionRun_e960 {
  strings:
    $key_e960 = { ba 0f [2] 9e 01 [2] b5 2d [2] 9b 0f [2] 8f 14 [2] 80 0e [2] 9e 13 [2] 9c 12 [2] 87 14 [2] 9b 13 [2] 87 3c }

  condition:
    any of them
}