rule TTP_XOR_QUAD_CurrentVersionRun_e053 {
  strings:
    $key_e053 = { b3 3c [2] 97 32 [2] bc 1e [2] 92 3c [2] 86 27 [2] 89 3d [2] 97 20 [2] 95 21 [2] 8e 27 [2] 92 20 [2] 8e 0f }

  condition:
    any of them
}