rule TTP_XOR_QUAD_CurrentVersionRun_eeb5 {
  strings:
    $key_eeb5 = { bd da [2] 99 d4 [2] b2 f8 [2] 9c da [2] 88 c1 [2] 87 db [2] 99 c6 [2] 9b c7 [2] 80 c1 [2] 9c c6 [2] 80 e9 }

  condition:
    any of them
}