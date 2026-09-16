rule TTP_XOR_QUAD_CurrentVersionRun_b3f9 {
  strings:
    $key_b3f9 = { e0 96 [2] c4 98 [2] ef b4 [2] c1 96 [2] d5 8d [2] da 97 [2] c4 8a [2] c6 8b [2] dd 8d [2] c1 8a [2] dd a5 }

  condition:
    any of them
}