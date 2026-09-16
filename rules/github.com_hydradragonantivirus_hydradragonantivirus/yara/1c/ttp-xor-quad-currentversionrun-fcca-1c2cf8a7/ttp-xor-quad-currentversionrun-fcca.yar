rule TTP_XOR_QUAD_CurrentVersionRun_fcca {
  strings:
    $key_fcca = { af a5 [2] 8b ab [2] a0 87 [2] 8e a5 [2] 9a be [2] 95 a4 [2] 8b b9 [2] 89 b8 [2] 92 be [2] 8e b9 [2] 92 96 }

  condition:
    any of them
}