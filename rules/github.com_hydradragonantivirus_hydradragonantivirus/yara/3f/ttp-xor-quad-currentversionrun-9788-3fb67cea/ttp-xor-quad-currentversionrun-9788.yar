rule TTP_XOR_QUAD_CurrentVersionRun_9788 {
  strings:
    $key_9788 = { c4 e7 [2] e0 e9 [2] cb c5 [2] e5 e7 [2] f1 fc [2] fe e6 [2] e0 fb [2] e2 fa [2] f9 fc [2] e5 fb [2] f9 d4 }

  condition:
    any of them
}