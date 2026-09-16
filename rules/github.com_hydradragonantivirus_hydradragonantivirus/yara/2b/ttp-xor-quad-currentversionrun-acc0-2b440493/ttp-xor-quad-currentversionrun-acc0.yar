rule TTP_XOR_QUAD_CurrentVersionRun_acc0 {
  strings:
    $key_acc0 = { ff af [2] db a1 [2] f0 8d [2] de af [2] ca b4 [2] c5 ae [2] db b3 [2] d9 b2 [2] c2 b4 [2] de b3 [2] c2 9c }

  condition:
    any of them
}