rule TTP_XOR_QUAD_CurrentVersionRun_8bb6 {
  strings:
    $key_8bb6 = { d8 d9 [2] fc d7 [2] d7 fb [2] f9 d9 [2] ed c2 [2] e2 d8 [2] fc c5 [2] fe c4 [2] e5 c2 [2] f9 c5 [2] e5 ea }

  condition:
    any of them
}