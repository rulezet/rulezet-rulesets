rule TTP_XOR_QUAD_CurrentVersionRun_35c8 {
  strings:
    $key_35c8 = { 66 a7 [2] 42 a9 [2] 69 85 [2] 47 a7 [2] 53 bc [2] 5c a6 [2] 42 bb [2] 40 ba [2] 5b bc [2] 47 bb [2] 5b 94 }

  condition:
    any of them
}