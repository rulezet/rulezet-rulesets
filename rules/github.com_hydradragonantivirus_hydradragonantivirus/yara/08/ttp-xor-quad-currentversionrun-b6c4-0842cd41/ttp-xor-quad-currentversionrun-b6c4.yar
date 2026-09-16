rule TTP_XOR_QUAD_CurrentVersionRun_b6c4 {
  strings:
    $key_b6c4 = { e5 ab [2] c1 a5 [2] ea 89 [2] c4 ab [2] d0 b0 [2] df aa [2] c1 b7 [2] c3 b6 [2] d8 b0 [2] c4 b7 [2] d8 98 }

  condition:
    any of them
}