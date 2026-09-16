rule TTP_XOR_QUAD_CurrentVersionRun_e01f {
  strings:
    $key_e01f = { b3 70 [2] 97 7e [2] bc 52 [2] 92 70 [2] 86 6b [2] 89 71 [2] 97 6c [2] 95 6d [2] 8e 6b [2] 92 6c [2] 8e 43 }

  condition:
    any of them
}