rule TTP_XOR_QUAD_CurrentVersionRun_e009 {
  strings:
    $key_e009 = { b3 66 [2] 97 68 [2] bc 44 [2] 92 66 [2] 86 7d [2] 89 67 [2] 97 7a [2] 95 7b [2] 8e 7d [2] 92 7a [2] 8e 55 }

  condition:
    any of them
}