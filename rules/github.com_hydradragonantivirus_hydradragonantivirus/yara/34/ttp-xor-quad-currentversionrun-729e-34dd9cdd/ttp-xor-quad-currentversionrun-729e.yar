rule TTP_XOR_QUAD_CurrentVersionRun_729e {
  strings:
    $key_729e = { 21 f1 [2] 05 ff [2] 2e d3 [2] 00 f1 [2] 14 ea [2] 1b f0 [2] 05 ed [2] 07 ec [2] 1c ea [2] 00 ed [2] 1c c2 }

  condition:
    any of them
}