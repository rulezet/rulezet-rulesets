rule TTP_XOR_QUAD_CurrentVersionRun_9fb1 {
  strings:
    $key_9fb1 = { cc de [2] e8 d0 [2] c3 fc [2] ed de [2] f9 c5 [2] f6 df [2] e8 c2 [2] ea c3 [2] f1 c5 [2] ed c2 [2] f1 ed }

  condition:
    any of them
}