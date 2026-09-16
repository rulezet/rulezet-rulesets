rule TTP_XOR_QUAD_CurrentVersionRun_f90b {
  strings:
    $key_f90b = { aa 64 [2] 8e 6a [2] a5 46 [2] 8b 64 [2] 9f 7f [2] 90 65 [2] 8e 78 [2] 8c 79 [2] 97 7f [2] 8b 78 [2] 97 57 }

  condition:
    any of them
}