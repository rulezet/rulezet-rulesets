rule TTP_XOR_QUAD_CurrentVersionRun_e02f {
  strings:
    $key_e02f = { b3 40 [2] 97 4e [2] bc 62 [2] 92 40 [2] 86 5b [2] 89 41 [2] 97 5c [2] 95 5d [2] 8e 5b [2] 92 5c [2] 8e 73 }

  condition:
    any of them
}