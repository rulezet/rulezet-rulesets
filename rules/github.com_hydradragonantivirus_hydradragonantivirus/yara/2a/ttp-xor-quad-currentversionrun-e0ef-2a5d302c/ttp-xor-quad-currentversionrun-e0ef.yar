rule TTP_XOR_QUAD_CurrentVersionRun_e0ef {
  strings:
    $key_e0ef = { b3 80 [2] 97 8e [2] bc a2 [2] 92 80 [2] 86 9b [2] 89 81 [2] 97 9c [2] 95 9d [2] 8e 9b [2] 92 9c [2] 8e b3 }

  condition:
    any of them
}