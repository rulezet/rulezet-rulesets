rule TTP_XOR_QUAD_CurrentVersionRun_e04f {
  strings:
    $key_e04f = { b3 20 [2] 97 2e [2] bc 02 [2] 92 20 [2] 86 3b [2] 89 21 [2] 97 3c [2] 95 3d [2] 8e 3b [2] 92 3c [2] 8e 13 }

  condition:
    any of them
}