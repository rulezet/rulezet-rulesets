rule TTP_XOR_QUAD_CurrentVersionRun_e028 {
  strings:
    $key_e028 = { b3 47 [2] 97 49 [2] bc 65 [2] 92 47 [2] 86 5c [2] 89 46 [2] 97 5b [2] 95 5a [2] 8e 5c [2] 92 5b [2] 8e 74 }

  condition:
    any of them
}