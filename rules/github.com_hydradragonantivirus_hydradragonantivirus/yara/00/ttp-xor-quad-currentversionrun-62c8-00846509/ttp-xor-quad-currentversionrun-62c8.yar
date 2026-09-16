rule TTP_XOR_QUAD_CurrentVersionRun_62c8 {
  strings:
    $key_62c8 = { 31 a7 [2] 15 a9 [2] 3e 85 [2] 10 a7 [2] 04 bc [2] 0b a6 [2] 15 bb [2] 17 ba [2] 0c bc [2] 10 bb [2] 0c 94 }

  condition:
    any of them
}