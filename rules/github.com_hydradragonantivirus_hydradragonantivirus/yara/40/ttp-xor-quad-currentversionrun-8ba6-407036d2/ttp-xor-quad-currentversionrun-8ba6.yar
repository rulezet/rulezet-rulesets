rule TTP_XOR_QUAD_CurrentVersionRun_8ba6 {
  strings:
    $key_8ba6 = { d8 c9 [2] fc c7 [2] d7 eb [2] f9 c9 [2] ed d2 [2] e2 c8 [2] fc d5 [2] fe d4 [2] e5 d2 [2] f9 d5 [2] e5 fa }

  condition:
    any of them
}