rule TTP_XOR_QUAD_CurrentVersionRun_e036 {
  strings:
    $key_e036 = { b3 59 [2] 97 57 [2] bc 7b [2] 92 59 [2] 86 42 [2] 89 58 [2] 97 45 [2] 95 44 [2] 8e 42 [2] 92 45 [2] 8e 6a }

  condition:
    any of them
}