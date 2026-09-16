rule TTP_XOR_QUAD_CurrentVersionRun_aa82 {
  strings:
    $key_aa82 = { f9 ed [2] dd e3 [2] f6 cf [2] d8 ed [2] cc f6 [2] c3 ec [2] dd f1 [2] df f0 [2] c4 f6 [2] d8 f1 [2] c4 de }

  condition:
    any of them
}