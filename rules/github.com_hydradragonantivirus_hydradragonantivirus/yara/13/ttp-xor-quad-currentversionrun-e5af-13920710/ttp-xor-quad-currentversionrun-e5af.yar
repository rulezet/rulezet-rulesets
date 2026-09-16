rule TTP_XOR_QUAD_CurrentVersionRun_e5af {
  strings:
    $key_e5af = { b6 c0 [2] 92 ce [2] b9 e2 [2] 97 c0 [2] 83 db [2] 8c c1 [2] 92 dc [2] 90 dd [2] 8b db [2] 97 dc [2] 8b f3 }

  condition:
    any of them
}