rule TTP_XOR_QUAD_CurrentVersionRun_e014 {
  strings:
    $key_e014 = { b3 7b [2] 97 75 [2] bc 59 [2] 92 7b [2] 86 60 [2] 89 7a [2] 97 67 [2] 95 66 [2] 8e 60 [2] 92 67 [2] 8e 48 }

  condition:
    any of them
}