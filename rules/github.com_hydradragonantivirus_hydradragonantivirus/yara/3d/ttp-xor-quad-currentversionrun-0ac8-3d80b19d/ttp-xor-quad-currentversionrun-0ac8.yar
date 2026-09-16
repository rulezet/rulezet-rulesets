rule TTP_XOR_QUAD_CurrentVersionRun_0ac8 {
  strings:
    $key_0ac8 = { 59 a7 [2] 7d a9 [2] 56 85 [2] 78 a7 [2] 6c bc [2] 63 a6 [2] 7d bb [2] 7f ba [2] 64 bc [2] 78 bb [2] 64 94 }

  condition:
    any of them
}