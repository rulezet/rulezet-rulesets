rule TTP_XOR_QUAD_CurrentVersionRun_e008 {
  strings:
    $key_e008 = { b3 67 [2] 97 69 [2] bc 45 [2] 92 67 [2] 86 7c [2] 89 66 [2] 97 7b [2] 95 7a [2] 8e 7c [2] 92 7b [2] 8e 54 }

  condition:
    any of them
}