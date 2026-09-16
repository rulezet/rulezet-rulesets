rule TTP_XOR_QUAD_CurrentVersionRun_e039 {
  strings:
    $key_e039 = { b3 56 [2] 97 58 [2] bc 74 [2] 92 56 [2] 86 4d [2] 89 57 [2] 97 4a [2] 95 4b [2] 8e 4d [2] 92 4a [2] 8e 65 }

  condition:
    any of them
}