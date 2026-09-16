rule TTP_XOR_QUAD_CurrentVersionRun_dfaf {
  strings:
    $key_dfaf = { 8c c0 [2] a8 ce [2] 83 e2 [2] ad c0 [2] b9 db [2] b6 c1 [2] a8 dc [2] aa dd [2] b1 db [2] ad dc [2] b1 f3 }

  condition:
    any of them
}