rule TTP_XOR_QUAD_CurrentVersionRun_e297 {
  strings:
    $key_e297 = { b1 f8 [2] 95 f6 [2] be da [2] 90 f8 [2] 84 e3 [2] 8b f9 [2] 95 e4 [2] 97 e5 [2] 8c e3 [2] 90 e4 [2] 8c cb }

  condition:
    any of them
}