rule TTP_XOR_QUAD_CurrentVersionRun_e068 {
  strings:
    $key_e068 = { b3 07 [2] 97 09 [2] bc 25 [2] 92 07 [2] 86 1c [2] 89 06 [2] 97 1b [2] 95 1a [2] 8e 1c [2] 92 1b [2] 8e 34 }

  condition:
    any of them
}