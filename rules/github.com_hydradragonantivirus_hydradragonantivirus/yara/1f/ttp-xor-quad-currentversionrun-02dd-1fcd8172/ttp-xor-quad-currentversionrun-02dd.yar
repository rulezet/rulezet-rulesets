rule TTP_XOR_QUAD_CurrentVersionRun_02dd {
  strings:
    $key_02dd = { 51 b2 [2] 75 bc [2] 5e 90 [2] 70 b2 [2] 64 a9 [2] 6b b3 [2] 75 ae [2] 77 af [2] 6c a9 [2] 70 ae [2] 6c 81 }

  condition:
    any of them
}