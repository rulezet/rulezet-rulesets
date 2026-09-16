rule TTP_XOR_QUAD_CurrentVersionRun_efc3 {
  strings:
    $key_efc3 = { bc ac [2] 98 a2 [2] b3 8e [2] 9d ac [2] 89 b7 [2] 86 ad [2] 98 b0 [2] 9a b1 [2] 81 b7 [2] 9d b0 [2] 81 9f }

  condition:
    any of them
}