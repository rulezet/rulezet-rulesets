rule TTP_XOR_QUAD_CurrentVersionRun_8b87 {
  strings:
    $key_8b87 = { d8 e8 [2] fc e6 [2] d7 ca [2] f9 e8 [2] ed f3 [2] e2 e9 [2] fc f4 [2] fe f5 [2] e5 f3 [2] f9 f4 [2] e5 db }

  condition:
    any of them
}