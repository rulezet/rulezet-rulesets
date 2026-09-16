rule TTP_XOR_QUAD_CurrentVersionRun_a9c9 {
  strings:
    $key_a9c9 = { fa a6 [2] de a8 [2] f5 84 [2] db a6 [2] cf bd [2] c0 a7 [2] de ba [2] dc bb [2] c7 bd [2] db ba [2] c7 95 }

  condition:
    any of them
}