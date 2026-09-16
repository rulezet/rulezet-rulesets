rule TTP_XOR_QUAD_CurrentVersionRun_bb82 {
  strings:
    $key_bb82 = { e8 ed [2] cc e3 [2] e7 cf [2] c9 ed [2] dd f6 [2] d2 ec [2] cc f1 [2] ce f0 [2] d5 f6 [2] c9 f1 [2] d5 de }

  condition:
    any of them
}