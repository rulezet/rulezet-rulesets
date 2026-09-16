rule TTP_XOR_QUAD_CurrentVersionRun_d2bc {
  strings:
    $key_d2bc = { 81 d3 [2] a5 dd [2] 8e f1 [2] a0 d3 [2] b4 c8 [2] bb d2 [2] a5 cf [2] a7 ce [2] bc c8 [2] a0 cf [2] bc e0 }

  condition:
    any of them
}