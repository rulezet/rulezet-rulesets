rule TTP_XOR_QUAD_CurrentVersionRun_d1ba {
  strings:
    $key_d1ba = { 82 d5 [2] a6 db [2] 8d f7 [2] a3 d5 [2] b7 ce [2] b8 d4 [2] a6 c9 [2] a4 c8 [2] bf ce [2] a3 c9 [2] bf e6 }

  condition:
    any of them
}