rule TTP_XOR_QUAD_CurrentVersionRun_fcd1 {
  strings:
    $key_fcd1 = { af be [2] 8b b0 [2] a0 9c [2] 8e be [2] 9a a5 [2] 95 bf [2] 8b a2 [2] 89 a3 [2] 92 a5 [2] 8e a2 [2] 92 8d }

  condition:
    any of them
}