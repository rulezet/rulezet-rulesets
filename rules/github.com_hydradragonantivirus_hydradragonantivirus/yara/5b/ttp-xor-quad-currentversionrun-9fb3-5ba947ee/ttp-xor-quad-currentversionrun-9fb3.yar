rule TTP_XOR_QUAD_CurrentVersionRun_9fb3 {
  strings:
    $key_9fb3 = { cc dc [2] e8 d2 [2] c3 fe [2] ed dc [2] f9 c7 [2] f6 dd [2] e8 c0 [2] ea c1 [2] f1 c7 [2] ed c0 [2] f1 ef }

  condition:
    any of them
}