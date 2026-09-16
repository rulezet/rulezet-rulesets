rule TTP_XOR_QUAD_CurrentVersionRun_15af {
  strings:
    $key_15af = { 46 c0 [2] 62 ce [2] 49 e2 [2] 67 c0 [2] 73 db [2] 7c c1 [2] 62 dc [2] 60 dd [2] 7b db [2] 67 dc [2] 7b f3 }

  condition:
    any of them
}