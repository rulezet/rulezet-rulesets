rule TTP_XOR_QUAD_CurrentVersionRun_daaf {
  strings:
    $key_daaf = { 89 c0 [2] ad ce [2] 86 e2 [2] a8 c0 [2] bc db [2] b3 c1 [2] ad dc [2] af dd [2] b4 db [2] a8 dc [2] b4 f3 }

  condition:
    any of them
}