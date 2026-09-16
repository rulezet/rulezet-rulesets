rule TTP_XOR_QUAD_CurrentVersionRun_e0a8 {
  strings:
    $key_e0a8 = { b3 c7 [2] 97 c9 [2] bc e5 [2] 92 c7 [2] 86 dc [2] 89 c6 [2] 97 db [2] 95 da [2] 8e dc [2] 92 db [2] 8e f4 }

  condition:
    any of them
}