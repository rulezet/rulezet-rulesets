rule TTP_XOR_QUAD_CurrentVersionRun_ccba {
  strings:
    $key_ccba = { 9f d5 [2] bb db [2] 90 f7 [2] be d5 [2] aa ce [2] a5 d4 [2] bb c9 [2] b9 c8 [2] a2 ce [2] be c9 [2] a2 e6 }

  condition:
    any of them
}