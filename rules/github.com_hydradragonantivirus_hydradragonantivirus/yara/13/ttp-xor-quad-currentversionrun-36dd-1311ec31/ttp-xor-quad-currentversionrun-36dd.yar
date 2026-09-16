rule TTP_XOR_QUAD_CurrentVersionRun_36dd {
  strings:
    $key_36dd = { 65 b2 [2] 41 bc [2] 6a 90 [2] 44 b2 [2] 50 a9 [2] 5f b3 [2] 41 ae [2] 43 af [2] 58 a9 [2] 44 ae [2] 58 81 }

  condition:
    any of them
}