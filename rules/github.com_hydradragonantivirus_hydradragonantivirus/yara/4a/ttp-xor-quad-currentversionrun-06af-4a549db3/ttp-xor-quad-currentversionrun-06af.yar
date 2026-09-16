rule TTP_XOR_QUAD_CurrentVersionRun_06af {
  strings:
    $key_06af = { 55 c0 [2] 71 ce [2] 5a e2 [2] 74 c0 [2] 60 db [2] 6f c1 [2] 71 dc [2] 73 dd [2] 68 db [2] 74 dc [2] 68 f3 }

  condition:
    any of them
}