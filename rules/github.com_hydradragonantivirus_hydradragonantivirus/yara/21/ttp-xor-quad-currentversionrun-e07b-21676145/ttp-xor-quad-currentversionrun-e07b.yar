rule TTP_XOR_QUAD_CurrentVersionRun_e07b {
  strings:
    $key_e07b = { b3 14 [2] 97 1a [2] bc 36 [2] 92 14 [2] 86 0f [2] 89 15 [2] 97 08 [2] 95 09 [2] 8e 0f [2] 92 08 [2] 8e 27 }

  condition:
    any of them
}