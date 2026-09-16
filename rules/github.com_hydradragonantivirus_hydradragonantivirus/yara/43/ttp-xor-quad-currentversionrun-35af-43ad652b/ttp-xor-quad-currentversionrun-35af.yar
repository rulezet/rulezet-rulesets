rule TTP_XOR_QUAD_CurrentVersionRun_35af {
  strings:
    $key_35af = { 66 c0 [2] 42 ce [2] 69 e2 [2] 47 c0 [2] 53 db [2] 5c c1 [2] 42 dc [2] 40 dd [2] 5b db [2] 47 dc [2] 5b f3 }

  condition:
    any of them
}