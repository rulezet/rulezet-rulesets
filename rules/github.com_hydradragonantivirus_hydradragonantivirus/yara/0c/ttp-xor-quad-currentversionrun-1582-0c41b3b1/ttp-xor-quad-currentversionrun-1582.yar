rule TTP_XOR_QUAD_CurrentVersionRun_1582 {
  strings:
    $key_1582 = { 46 ed [2] 62 e3 [2] 49 cf [2] 67 ed [2] 73 f6 [2] 7c ec [2] 62 f1 [2] 60 f0 [2] 7b f6 [2] 67 f1 [2] 7b de }

  condition:
    any of them
}