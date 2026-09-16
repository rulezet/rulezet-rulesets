rule TTP_XOR_QUAD_CurrentVersionRun_e0a9 {
  strings:
    $key_e0a9 = { b3 c6 [2] 97 c8 [2] bc e4 [2] 92 c6 [2] 86 dd [2] 89 c7 [2] 97 da [2] 95 db [2] 8e dd [2] 92 da [2] 8e f5 }

  condition:
    any of them
}