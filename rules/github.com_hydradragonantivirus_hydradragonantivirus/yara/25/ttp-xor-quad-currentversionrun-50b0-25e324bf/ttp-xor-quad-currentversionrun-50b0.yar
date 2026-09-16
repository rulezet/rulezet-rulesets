rule TTP_XOR_QUAD_CurrentVersionRun_50b0 {
  strings:
    $key_50b0 = { 03 df [2] 27 d1 [2] 0c fd [2] 22 df [2] 36 c4 [2] 39 de [2] 27 c3 [2] 25 c2 [2] 3e c4 [2] 22 c3 [2] 3e ec }

  condition:
    any of them
}