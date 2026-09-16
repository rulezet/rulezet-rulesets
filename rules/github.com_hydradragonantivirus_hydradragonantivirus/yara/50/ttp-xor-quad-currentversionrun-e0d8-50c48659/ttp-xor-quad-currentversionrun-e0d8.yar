rule TTP_XOR_QUAD_CurrentVersionRun_e0d8 {
  strings:
    $key_e0d8 = { b3 b7 [2] 97 b9 [2] bc 95 [2] 92 b7 [2] 86 ac [2] 89 b6 [2] 97 ab [2] 95 aa [2] 8e ac [2] 92 ab [2] 8e 84 }

  condition:
    any of them
}