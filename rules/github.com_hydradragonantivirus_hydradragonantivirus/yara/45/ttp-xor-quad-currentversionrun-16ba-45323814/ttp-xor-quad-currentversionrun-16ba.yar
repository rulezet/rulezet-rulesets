rule TTP_XOR_QUAD_CurrentVersionRun_16ba {
  strings:
    $key_16ba = { 45 d5 [2] 61 db [2] 4a f7 [2] 64 d5 [2] 70 ce [2] 7f d4 [2] 61 c9 [2] 63 c8 [2] 78 ce [2] 64 c9 [2] 78 e6 }

  condition:
    any of them
}