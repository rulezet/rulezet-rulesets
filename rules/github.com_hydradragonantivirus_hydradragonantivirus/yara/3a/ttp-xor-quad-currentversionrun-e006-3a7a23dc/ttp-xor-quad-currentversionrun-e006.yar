rule TTP_XOR_QUAD_CurrentVersionRun_e006 {
  strings:
    $key_e006 = { b3 69 [2] 97 67 [2] bc 4b [2] 92 69 [2] 86 72 [2] 89 68 [2] 97 75 [2] 95 74 [2] 8e 72 [2] 92 75 [2] 8e 5a }

  condition:
    any of them
}