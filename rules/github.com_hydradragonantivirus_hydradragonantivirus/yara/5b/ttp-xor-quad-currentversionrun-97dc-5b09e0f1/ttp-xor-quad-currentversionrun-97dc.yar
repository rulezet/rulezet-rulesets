rule TTP_XOR_QUAD_CurrentVersionRun_97dc {
  strings:
    $key_97dc = { c4 b3 [2] e0 bd [2] cb 91 [2] e5 b3 [2] f1 a8 [2] fe b2 [2] e0 af [2] e2 ae [2] f9 a8 [2] e5 af [2] f9 80 }

  condition:
    any of them
}