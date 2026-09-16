rule TTP_XOR_QUAD_CurrentVersionRun_d2bd {
  strings:
    $key_d2bd = { 81 d2 [2] a5 dc [2] 8e f0 [2] a0 d2 [2] b4 c9 [2] bb d3 [2] a5 ce [2] a7 cf [2] bc c9 [2] a0 ce [2] bc e1 }

  condition:
    any of them
}