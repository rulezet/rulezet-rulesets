rule TTP_XOR_QUAD_CurrentVersionRun_e01b {
  strings:
    $key_e01b = { b3 74 [2] 97 7a [2] bc 56 [2] 92 74 [2] 86 6f [2] 89 75 [2] 97 68 [2] 95 69 [2] 8e 6f [2] 92 68 [2] 8e 47 }

  condition:
    any of them
}