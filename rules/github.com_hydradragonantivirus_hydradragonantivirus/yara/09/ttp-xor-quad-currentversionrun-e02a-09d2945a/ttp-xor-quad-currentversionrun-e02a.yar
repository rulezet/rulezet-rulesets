rule TTP_XOR_QUAD_CurrentVersionRun_e02a {
  strings:
    $key_e02a = { b3 45 [2] 97 4b [2] bc 67 [2] 92 45 [2] 86 5e [2] 89 44 [2] 97 59 [2] 95 58 [2] 8e 5e [2] 92 59 [2] 8e 76 }

  condition:
    any of them
}