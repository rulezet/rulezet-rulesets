rule TTP_XOR_QUAD_CurrentVersionRun_57b5 {
  strings:
    $key_57b5 = { 04 da [2] 20 d4 [2] 0b f8 [2] 25 da [2] 31 c1 [2] 3e db [2] 20 c6 [2] 22 c7 [2] 39 c1 [2] 25 c6 [2] 39 e9 }

  condition:
    any of them
}