rule TTP_XOR_QUAD_CurrentVersionRun_ceca {
  strings:
    $key_ceca = { 9d a5 [2] b9 ab [2] 92 87 [2] bc a5 [2] a8 be [2] a7 a4 [2] b9 b9 [2] bb b8 [2] a0 be [2] bc b9 [2] a0 96 }

  condition:
    any of them
}