rule TTP_XOR_QUAD_CurrentVersionRun_e0d9 {
  strings:
    $key_e0d9 = { b3 b6 [2] 97 b8 [2] bc 94 [2] 92 b6 [2] 86 ad [2] 89 b7 [2] 97 aa [2] 95 ab [2] 8e ad [2] 92 aa [2] 8e 85 }

  condition:
    any of them
}