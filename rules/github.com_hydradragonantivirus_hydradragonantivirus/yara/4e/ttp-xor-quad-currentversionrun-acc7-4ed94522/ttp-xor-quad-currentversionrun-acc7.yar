rule TTP_XOR_QUAD_CurrentVersionRun_acc7 {
  strings:
    $key_acc7 = { ff a8 [2] db a6 [2] f0 8a [2] de a8 [2] ca b3 [2] c5 a9 [2] db b4 [2] d9 b5 [2] c2 b3 [2] de b4 [2] c2 9b }

  condition:
    any of them
}