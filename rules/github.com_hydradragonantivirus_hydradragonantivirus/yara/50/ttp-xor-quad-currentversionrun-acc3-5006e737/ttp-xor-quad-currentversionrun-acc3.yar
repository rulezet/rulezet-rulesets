rule TTP_XOR_QUAD_CurrentVersionRun_acc3 {
  strings:
    $key_acc3 = { ff ac [2] db a2 [2] f0 8e [2] de ac [2] ca b7 [2] c5 ad [2] db b0 [2] d9 b1 [2] c2 b7 [2] de b0 [2] c2 9f }

  condition:
    any of them
}