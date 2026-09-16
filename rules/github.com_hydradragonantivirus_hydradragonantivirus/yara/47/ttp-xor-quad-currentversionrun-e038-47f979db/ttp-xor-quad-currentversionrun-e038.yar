rule TTP_XOR_QUAD_CurrentVersionRun_e038 {
  strings:
    $key_e038 = { b3 57 [2] 97 59 [2] bc 75 [2] 92 57 [2] 86 4c [2] 89 56 [2] 97 4b [2] 95 4a [2] 8e 4c [2] 92 4b [2] 8e 64 }

  condition:
    any of them
}