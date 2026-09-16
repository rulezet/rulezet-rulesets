rule TTP_XOR_QUAD_CurrentVersionRun_978a {
  strings:
    $key_978a = { c4 e5 [2] e0 eb [2] cb c7 [2] e5 e5 [2] f1 fe [2] fe e4 [2] e0 f9 [2] e2 f8 [2] f9 fe [2] e5 f9 [2] f9 d6 }

  condition:
    any of them
}