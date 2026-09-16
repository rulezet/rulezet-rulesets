rule TTP_XOR_QUAD_CurrentVersionRun_e0b1 {
  strings:
    $key_e0b1 = { b3 de [2] 97 d0 [2] bc fc [2] 92 de [2] 86 c5 [2] 89 df [2] 97 c2 [2] 95 c3 [2] 8e c5 [2] 92 c2 [2] 8e ed }

  condition:
    any of them
}