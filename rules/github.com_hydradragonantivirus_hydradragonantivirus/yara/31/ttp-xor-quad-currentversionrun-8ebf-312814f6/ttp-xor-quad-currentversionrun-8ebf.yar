rule TTP_XOR_QUAD_CurrentVersionRun_8ebf {
  strings:
    $key_8ebf = { dd d0 [2] f9 de [2] d2 f2 [2] fc d0 [2] e8 cb [2] e7 d1 [2] f9 cc [2] fb cd [2] e0 cb [2] fc cc [2] e0 e3 }

  condition:
    any of them
}