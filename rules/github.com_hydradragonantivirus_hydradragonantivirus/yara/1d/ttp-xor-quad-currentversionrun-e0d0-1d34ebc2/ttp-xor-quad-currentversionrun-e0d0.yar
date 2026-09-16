rule TTP_XOR_QUAD_CurrentVersionRun_e0d0 {
  strings:
    $key_e0d0 = { b3 bf [2] 97 b1 [2] bc 9d [2] 92 bf [2] 86 a4 [2] 89 be [2] 97 a3 [2] 95 a2 [2] 8e a4 [2] 92 a3 [2] 8e 8c }

  condition:
    any of them
}