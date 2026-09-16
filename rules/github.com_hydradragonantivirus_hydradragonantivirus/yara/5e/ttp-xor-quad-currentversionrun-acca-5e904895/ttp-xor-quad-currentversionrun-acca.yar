rule TTP_XOR_QUAD_CurrentVersionRun_acca {
  strings:
    $key_acca = { ff a5 [2] db ab [2] f0 87 [2] de a5 [2] ca be [2] c5 a4 [2] db b9 [2] d9 b8 [2] c2 be [2] de b9 [2] c2 96 }

  condition:
    any of them
}