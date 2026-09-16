rule TTP_XOR_QUAD_CurrentVersionRun_c4ba {
  strings:
    $key_c4ba = { 97 d5 [2] b3 db [2] 98 f7 [2] b6 d5 [2] a2 ce [2] ad d4 [2] b3 c9 [2] b1 c8 [2] aa ce [2] b6 c9 [2] aa e6 }

  condition:
    any of them
}