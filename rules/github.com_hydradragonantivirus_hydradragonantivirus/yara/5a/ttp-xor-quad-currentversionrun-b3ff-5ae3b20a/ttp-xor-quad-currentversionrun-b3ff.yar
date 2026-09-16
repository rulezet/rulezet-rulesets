rule TTP_XOR_QUAD_CurrentVersionRun_b3ff {
  strings:
    $key_b3ff = { e0 90 [2] c4 9e [2] ef b2 [2] c1 90 [2] d5 8b [2] da 91 [2] c4 8c [2] c6 8d [2] dd 8b [2] c1 8c [2] dd a3 }

  condition:
    any of them
}