rule TTP_XOR_QUAD_CurrentVersionRun_e027 {
  strings:
    $key_e027 = { b3 48 [2] 97 46 [2] bc 6a [2] 92 48 [2] 86 53 [2] 89 49 [2] 97 54 [2] 95 55 [2] 8e 53 [2] 92 54 [2] 8e 7b }

  condition:
    any of them
}