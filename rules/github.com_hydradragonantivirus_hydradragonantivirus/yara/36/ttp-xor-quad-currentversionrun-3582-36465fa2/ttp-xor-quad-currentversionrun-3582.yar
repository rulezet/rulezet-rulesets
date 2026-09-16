rule TTP_XOR_QUAD_CurrentVersionRun_3582 {
  strings:
    $key_3582 = { 66 ed [2] 42 e3 [2] 69 cf [2] 47 ed [2] 53 f6 [2] 5c ec [2] 42 f1 [2] 40 f0 [2] 5b f6 [2] 47 f1 [2] 5b de }

  condition:
    any of them
}