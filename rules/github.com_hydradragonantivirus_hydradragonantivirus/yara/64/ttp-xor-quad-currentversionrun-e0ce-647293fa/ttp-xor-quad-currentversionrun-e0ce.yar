rule TTP_XOR_QUAD_CurrentVersionRun_e0ce {
  strings:
    $key_e0ce = { b3 a1 [2] 97 af [2] bc 83 [2] 92 a1 [2] 86 ba [2] 89 a0 [2] 97 bd [2] 95 bc [2] 8e ba [2] 92 bd [2] 8e 92 }

  condition:
    any of them
}