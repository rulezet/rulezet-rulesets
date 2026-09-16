rule TTP_XOR_QUAD_CurrentVersionRun_8b82 {
  strings:
    $key_8b82 = { d8 ed [2] fc e3 [2] d7 cf [2] f9 ed [2] ed f6 [2] e2 ec [2] fc f1 [2] fe f0 [2] e5 f6 [2] f9 f1 [2] e5 de }

  condition:
    any of them
}