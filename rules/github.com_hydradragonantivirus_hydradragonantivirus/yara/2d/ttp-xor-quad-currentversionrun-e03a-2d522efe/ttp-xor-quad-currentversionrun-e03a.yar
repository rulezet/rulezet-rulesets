rule TTP_XOR_QUAD_CurrentVersionRun_e03a {
  strings:
    $key_e03a = { b3 55 [2] 97 5b [2] bc 77 [2] 92 55 [2] 86 4e [2] 89 54 [2] 97 49 [2] 95 48 [2] 8e 4e [2] 92 49 [2] 8e 66 }

  condition:
    any of them
}