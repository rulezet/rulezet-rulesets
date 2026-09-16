rule TTP_XOR_QUAD_CurrentVersionRun_e0d1 {
  strings:
    $key_e0d1 = { b3 be [2] 97 b0 [2] bc 9c [2] 92 be [2] 86 a5 [2] 89 bf [2] 97 a2 [2] 95 a3 [2] 8e a5 [2] 92 a2 [2] 8e 8d }

  condition:
    any of them
}