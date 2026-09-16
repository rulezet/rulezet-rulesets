rule TTP_XOR_QUAD_CurrentVersionRun_8e96 {
  strings:
    $key_8e96 = { dd f9 [2] f9 f7 [2] d2 db [2] fc f9 [2] e8 e2 [2] e7 f8 [2] f9 e5 [2] fb e4 [2] e0 e2 [2] fc e5 [2] e0 ca }

  condition:
    any of them
}