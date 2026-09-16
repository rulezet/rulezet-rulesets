rule TTP_XOR_QUAD_CurrentVersionRun_97dd {
  strings:
    $key_97dd = { c4 b2 [2] e0 bc [2] cb 90 [2] e5 b2 [2] f1 a9 [2] fe b3 [2] e0 ae [2] e2 af [2] f9 a9 [2] e5 ae [2] f9 81 }

  condition:
    any of them
}