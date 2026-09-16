rule TTP_XOR_QUAD_CurrentVersionRun_62b0 {
  strings:
    $key_62b0 = { 31 df [2] 15 d1 [2] 3e fd [2] 10 df [2] 04 c4 [2] 0b de [2] 15 c3 [2] 17 c2 [2] 0c c4 [2] 10 c3 [2] 0c ec }

  condition:
    any of them
}