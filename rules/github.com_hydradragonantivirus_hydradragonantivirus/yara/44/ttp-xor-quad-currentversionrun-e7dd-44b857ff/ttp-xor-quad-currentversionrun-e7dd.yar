rule TTP_XOR_QUAD_CurrentVersionRun_e7dd {
  strings:
    $key_e7dd = { b4 b2 [2] 90 bc [2] bb 90 [2] 95 b2 [2] 81 a9 [2] 8e b3 [2] 90 ae [2] 92 af [2] 89 a9 [2] 95 ae [2] 89 81 }

  condition:
    any of them
}