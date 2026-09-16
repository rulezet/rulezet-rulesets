rule TTP_XOR_QUAD_CurrentVersionRun_acc4 {
  strings:
    $key_acc4 = { ff ab [2] db a5 [2] f0 89 [2] de ab [2] ca b0 [2] c5 aa [2] db b7 [2] d9 b6 [2] c2 b0 [2] de b7 [2] c2 98 }

  condition:
    any of them
}