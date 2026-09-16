rule TTP_XOR_QUAD_CurrentVersionRun_e007 {
  strings:
    $key_e007 = { b3 68 [2] 97 66 [2] bc 4a [2] 92 68 [2] 86 73 [2] 89 69 [2] 97 74 [2] 95 75 [2] 8e 73 [2] 92 74 [2] 8e 5b }

  condition:
    any of them
}