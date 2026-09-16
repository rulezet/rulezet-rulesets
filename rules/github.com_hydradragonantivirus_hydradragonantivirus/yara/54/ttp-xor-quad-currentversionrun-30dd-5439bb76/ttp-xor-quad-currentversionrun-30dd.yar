rule TTP_XOR_QUAD_CurrentVersionRun_30dd {
  strings:
    $key_30dd = { 63 b2 [2] 47 bc [2] 6c 90 [2] 42 b2 [2] 56 a9 [2] 59 b3 [2] 47 ae [2] 45 af [2] 5e a9 [2] 42 ae [2] 5e 81 }

  condition:
    any of them
}