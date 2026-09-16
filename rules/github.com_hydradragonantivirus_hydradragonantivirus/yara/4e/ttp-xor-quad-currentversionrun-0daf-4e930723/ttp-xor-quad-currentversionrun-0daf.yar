rule TTP_XOR_QUAD_CurrentVersionRun_0daf {
  strings:
    $key_0daf = { 5e c0 [2] 7a ce [2] 51 e2 [2] 7f c0 [2] 6b db [2] 64 c1 [2] 7a dc [2] 78 dd [2] 63 db [2] 7f dc [2] 63 f3 }

  condition:
    any of them
}