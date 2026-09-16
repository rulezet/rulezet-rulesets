rule TTP_XOR_QUAD_CurrentVersionRun_3ac8 {
  strings:
    $key_3ac8 = { 69 a7 [2] 4d a9 [2] 66 85 [2] 48 a7 [2] 5c bc [2] 53 a6 [2] 4d bb [2] 4f ba [2] 54 bc [2] 48 bb [2] 54 94 }

  condition:
    any of them
}