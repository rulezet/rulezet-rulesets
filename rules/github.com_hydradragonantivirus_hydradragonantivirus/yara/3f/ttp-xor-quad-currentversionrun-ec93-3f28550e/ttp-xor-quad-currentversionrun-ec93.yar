rule TTP_XOR_QUAD_CurrentVersionRun_ec93 {
  strings:
    $key_ec93 = { bf fc [2] 9b f2 [2] b0 de [2] 9e fc [2] 8a e7 [2] 85 fd [2] 9b e0 [2] 99 e1 [2] 82 e7 [2] 9e e0 [2] 82 cf }

  condition:
    any of them
}