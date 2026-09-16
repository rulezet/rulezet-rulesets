rule TTP_XOR_QUAD_CurrentVersionRun_d1b3 {
  strings:
    $key_d1b3 = { 82 dc [2] a6 d2 [2] 8d fe [2] a3 dc [2] b7 c7 [2] b8 dd [2] a6 c0 [2] a4 c1 [2] bf c7 [2] a3 c0 [2] bf ef }

  condition:
    any of them
}