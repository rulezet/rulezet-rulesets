rule TTP_XOR_QUAD_CurrentVersionRun_7eb6 {
  strings:
    $key_7eb6 = { 2d d9 [2] 09 d7 [2] 22 fb [2] 0c d9 [2] 18 c2 [2] 17 d8 [2] 09 c5 [2] 0b c4 [2] 10 c2 [2] 0c c5 [2] 10 ea }

  condition:
    any of them
}