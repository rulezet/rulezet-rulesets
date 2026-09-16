rule TTP_XOR_QUAD_CurrentVersionRun_11af {
  strings:
    $key_11af = { 42 c0 [2] 66 ce [2] 4d e2 [2] 63 c0 [2] 77 db [2] 78 c1 [2] 66 dc [2] 64 dd [2] 7f db [2] 63 dc [2] 7f f3 }

  condition:
    any of them
}