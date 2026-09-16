rule TTP_XOR_QUAD_CurrentVersionRun_98af {
  strings:
    $key_98af = { cb c0 [2] ef ce [2] c4 e2 [2] ea c0 [2] fe db [2] f1 c1 [2] ef dc [2] ed dd [2] f6 db [2] ea dc [2] f6 f3 }

  condition:
    any of them
}