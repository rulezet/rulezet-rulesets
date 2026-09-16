rule TTP_XOR_QUAD_CurrentVersionRun_76af {
  strings:
    $key_76af = { 25 c0 [2] 01 ce [2] 2a e2 [2] 04 c0 [2] 10 db [2] 1f c1 [2] 01 dc [2] 03 dd [2] 18 db [2] 04 dc [2] 18 f3 }

  condition:
    any of them
}