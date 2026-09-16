rule TTP_XOR_QUAD_CurrentVersionRun_e03f {
  strings:
    $key_e03f = { b3 50 [2] 97 5e [2] bc 72 [2] 92 50 [2] 86 4b [2] 89 51 [2] 97 4c [2] 95 4d [2] 8e 4b [2] 92 4c [2] 8e 63 }

  condition:
    any of them
}