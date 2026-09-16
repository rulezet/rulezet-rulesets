rule TTP_XOR_QUAD_CurrentVersionRun_bbba {
  strings:
    $key_bbba = { e8 d5 [2] cc db [2] e7 f7 [2] c9 d5 [2] dd ce [2] d2 d4 [2] cc c9 [2] ce c8 [2] d5 ce [2] c9 c9 [2] d5 e6 }

  condition:
    any of them
}