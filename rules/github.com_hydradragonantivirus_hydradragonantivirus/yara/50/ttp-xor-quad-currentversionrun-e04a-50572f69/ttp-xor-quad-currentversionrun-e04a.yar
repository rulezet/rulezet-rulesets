rule TTP_XOR_QUAD_CurrentVersionRun_e04a {
  strings:
    $key_e04a = { b3 25 [2] 97 2b [2] bc 07 [2] 92 25 [2] 86 3e [2] 89 24 [2] 97 39 [2] 95 38 [2] 8e 3e [2] 92 39 [2] 8e 16 }

  condition:
    any of them
}