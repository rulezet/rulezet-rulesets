rule TTP_XOR_QUAD_CurrentVersionRun_e03b {
  strings:
    $key_e03b = { b3 54 [2] 97 5a [2] bc 76 [2] 92 54 [2] 86 4f [2] 89 55 [2] 97 48 [2] 95 49 [2] 8e 4f [2] 92 48 [2] 8e 67 }

  condition:
    any of them
}