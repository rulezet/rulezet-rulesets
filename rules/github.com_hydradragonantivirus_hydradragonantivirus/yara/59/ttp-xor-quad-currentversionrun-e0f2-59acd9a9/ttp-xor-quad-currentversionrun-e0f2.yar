rule TTP_XOR_QUAD_CurrentVersionRun_e0f2 {
  strings:
    $key_e0f2 = { b3 9d [2] 97 93 [2] bc bf [2] 92 9d [2] 86 86 [2] 89 9c [2] 97 81 [2] 95 80 [2] 8e 86 [2] 92 81 [2] 8e ae }

  condition:
    any of them
}