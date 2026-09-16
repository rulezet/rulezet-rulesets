rule TTP_XOR_QUAD_CurrentVersionRun_e034 {
  strings:
    $key_e034 = { b3 5b [2] 97 55 [2] bc 79 [2] 92 5b [2] 86 40 [2] 89 5a [2] 97 47 [2] 95 46 [2] 8e 40 [2] 92 47 [2] 8e 68 }

  condition:
    any of them
}