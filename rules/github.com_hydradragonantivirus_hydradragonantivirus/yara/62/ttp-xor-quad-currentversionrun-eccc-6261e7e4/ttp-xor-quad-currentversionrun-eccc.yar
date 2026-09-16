rule TTP_XOR_QUAD_CurrentVersionRun_eccc {
  strings:
    $key_eccc = { bf a3 [2] 9b ad [2] b0 81 [2] 9e a3 [2] 8a b8 [2] 85 a2 [2] 9b bf [2] 99 be [2] 82 b8 [2] 9e bf [2] 82 90 }

  condition:
    any of them
}