rule TTP_XOR_QUAD_CurrentVersionRun_e03c {
  strings:
    $key_e03c = { b3 53 [2] 97 5d [2] bc 71 [2] 92 53 [2] 86 48 [2] 89 52 [2] 97 4f [2] 95 4e [2] 8e 48 [2] 92 4f [2] 8e 60 }

  condition:
    any of them
}