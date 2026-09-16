rule TTP_XOR_QUAD_CurrentVersionRun_beb0 {
  strings:
    $key_beb0 = { ed df [2] c9 d1 [2] e2 fd [2] cc df [2] d8 c4 [2] d7 de [2] c9 c3 [2] cb c2 [2] d0 c4 [2] cc c3 [2] d0 ec }

  condition:
    any of them
}