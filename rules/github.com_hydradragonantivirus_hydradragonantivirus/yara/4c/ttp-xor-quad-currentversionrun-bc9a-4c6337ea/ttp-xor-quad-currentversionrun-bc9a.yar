rule TTP_XOR_QUAD_CurrentVersionRun_bc9a {
  strings:
    $key_bc9a = { ef f5 [2] cb fb [2] e0 d7 [2] ce f5 [2] da ee [2] d5 f4 [2] cb e9 [2] c9 e8 [2] d2 ee [2] ce e9 [2] d2 c6 }

  condition:
    any of them
}