rule TTP_XOR_QUAD_CurrentVersionRun_9793 {
  strings:
    $key_9793 = { c4 fc [2] e0 f2 [2] cb de [2] e5 fc [2] f1 e7 [2] fe fd [2] e0 e0 [2] e2 e1 [2] f9 e7 [2] e5 e0 [2] f9 cf }

  condition:
    any of them
}