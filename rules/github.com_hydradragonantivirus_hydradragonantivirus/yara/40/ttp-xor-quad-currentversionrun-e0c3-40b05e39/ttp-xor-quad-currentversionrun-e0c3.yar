rule TTP_XOR_QUAD_CurrentVersionRun_e0c3 {
  strings:
    $key_e0c3 = { b3 ac [2] 97 a2 [2] bc 8e [2] 92 ac [2] 86 b7 [2] 89 ad [2] 97 b0 [2] 95 b1 [2] 8e b7 [2] 92 b0 [2] 8e 9f }

  condition:
    any of them
}