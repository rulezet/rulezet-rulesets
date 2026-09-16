rule TTP_XOR_QUAD_CurrentVersionRun_e01e {
  strings:
    $key_e01e = { b3 71 [2] 97 7f [2] bc 53 [2] 92 71 [2] 86 6a [2] 89 70 [2] 97 6d [2] 95 6c [2] 8e 6a [2] 92 6d [2] 8e 42 }

  condition:
    any of them
}