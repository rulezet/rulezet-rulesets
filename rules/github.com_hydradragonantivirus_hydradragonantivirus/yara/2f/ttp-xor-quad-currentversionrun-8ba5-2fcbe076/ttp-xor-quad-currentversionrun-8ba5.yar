rule TTP_XOR_QUAD_CurrentVersionRun_8ba5 {
  strings:
    $key_8ba5 = { d8 ca [2] fc c4 [2] d7 e8 [2] f9 ca [2] ed d1 [2] e2 cb [2] fc d6 [2] fe d7 [2] e5 d1 [2] f9 d6 [2] e5 f9 }

  condition:
    any of them
}