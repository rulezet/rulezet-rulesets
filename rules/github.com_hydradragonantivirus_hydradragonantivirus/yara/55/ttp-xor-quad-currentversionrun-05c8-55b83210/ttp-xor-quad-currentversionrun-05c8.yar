rule TTP_XOR_QUAD_CurrentVersionRun_05c8 {
  strings:
    $key_05c8 = { 56 a7 [2] 72 a9 [2] 59 85 [2] 77 a7 [2] 63 bc [2] 6c a6 [2] 72 bb [2] 70 ba [2] 6b bc [2] 77 bb [2] 6b 94 }

  condition:
    any of them
}