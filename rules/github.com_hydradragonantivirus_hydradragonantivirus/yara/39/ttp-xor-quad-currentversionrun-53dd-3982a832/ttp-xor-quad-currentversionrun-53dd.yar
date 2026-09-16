rule TTP_XOR_QUAD_CurrentVersionRun_53dd {
  strings:
    $key_53dd = { 00 b2 [2] 24 bc [2] 0f 90 [2] 21 b2 [2] 35 a9 [2] 3a b3 [2] 24 ae [2] 26 af [2] 3d a9 [2] 21 ae [2] 3d 81 }

  condition:
    any of them
}