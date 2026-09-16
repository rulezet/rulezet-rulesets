rule TTP_XOR_QUAD_CurrentVersionRun_cbba {
  strings:
    $key_cbba = { 98 d5 [2] bc db [2] 97 f7 [2] b9 d5 [2] ad ce [2] a2 d4 [2] bc c9 [2] be c8 [2] a5 ce [2] b9 c9 [2] a5 e6 }

  condition:
    any of them
}