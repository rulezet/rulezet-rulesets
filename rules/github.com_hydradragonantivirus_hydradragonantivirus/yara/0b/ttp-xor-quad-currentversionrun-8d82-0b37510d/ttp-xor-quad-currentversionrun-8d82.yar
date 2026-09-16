rule TTP_XOR_QUAD_CurrentVersionRun_8d82 {
  strings:
    $key_8d82 = { de ed [2] fa e3 [2] d1 cf [2] ff ed [2] eb f6 [2] e4 ec [2] fa f1 [2] f8 f0 [2] e3 f6 [2] ff f1 [2] e3 de }

  condition:
    any of them
}