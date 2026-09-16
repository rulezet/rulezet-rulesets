rule TTP_XOR_QUAD_CurrentVersionRun_4182 {
  strings:
    $key_4182 = { 12 ed [2] 36 e3 [2] 1d cf [2] 33 ed [2] 27 f6 [2] 28 ec [2] 36 f1 [2] 34 f0 [2] 2f f6 [2] 33 f1 [2] 2f de }

  condition:
    any of them
}