rule TTP_XOR_QUAD_CurrentVersionRun_a9d1 {
  strings:
    $key_a9d1 = { fa be [2] de b0 [2] f5 9c [2] db be [2] cf a5 [2] c0 bf [2] de a2 [2] dc a3 [2] c7 a5 [2] db a2 [2] c7 8d }

  condition:
    any of them
}