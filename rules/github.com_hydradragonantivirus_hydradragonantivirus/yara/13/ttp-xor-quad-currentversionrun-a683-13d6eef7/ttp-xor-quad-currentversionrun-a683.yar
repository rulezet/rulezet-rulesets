rule TTP_XOR_QUAD_CurrentVersionRun_a683 {
  strings:
    $key_a683 = { f5 ec [2] d1 e2 [2] fa ce [2] d4 ec [2] c0 f7 [2] cf ed [2] d1 f0 [2] d3 f1 [2] c8 f7 [2] d4 f0 [2] c8 df }

  condition:
    any of them
}