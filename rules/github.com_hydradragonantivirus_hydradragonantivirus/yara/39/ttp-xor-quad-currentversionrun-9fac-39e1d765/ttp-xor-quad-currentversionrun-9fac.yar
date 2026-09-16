rule TTP_XOR_QUAD_CurrentVersionRun_9fac {
  strings:
    $key_9fac = { cc c3 [2] e8 cd [2] c3 e1 [2] ed c3 [2] f9 d8 [2] f6 c2 [2] e8 df [2] ea de [2] f1 d8 [2] ed df [2] f1 f0 }

  condition:
    any of them
}