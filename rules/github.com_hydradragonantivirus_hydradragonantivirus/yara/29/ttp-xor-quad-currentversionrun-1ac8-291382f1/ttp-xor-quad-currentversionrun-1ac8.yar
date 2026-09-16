rule TTP_XOR_QUAD_CurrentVersionRun_1ac8 {
  strings:
    $key_1ac8 = { 49 a7 [2] 6d a9 [2] 46 85 [2] 68 a7 [2] 7c bc [2] 73 a6 [2] 6d bb [2] 6f ba [2] 74 bc [2] 68 bb [2] 74 94 }

  condition:
    any of them
}