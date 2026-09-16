rule TTP_XOR_QUAD_CurrentVersionRun_56ba {
  strings:
    $key_56ba = { 05 d5 [2] 21 db [2] 0a f7 [2] 24 d5 [2] 30 ce [2] 3f d4 [2] 21 c9 [2] 23 c8 [2] 38 ce [2] 24 c9 [2] 38 e6 }

  condition:
    any of them
}