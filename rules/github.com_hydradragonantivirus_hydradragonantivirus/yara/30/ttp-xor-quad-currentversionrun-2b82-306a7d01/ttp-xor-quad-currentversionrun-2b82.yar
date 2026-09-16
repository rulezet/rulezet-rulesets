rule TTP_XOR_QUAD_CurrentVersionRun_2b82 {
  strings:
    $key_2b82 = { 78 ed [2] 5c e3 [2] 77 cf [2] 59 ed [2] 4d f6 [2] 42 ec [2] 5c f1 [2] 5e f0 [2] 45 f6 [2] 59 f1 [2] 45 de }

  condition:
    any of them
}