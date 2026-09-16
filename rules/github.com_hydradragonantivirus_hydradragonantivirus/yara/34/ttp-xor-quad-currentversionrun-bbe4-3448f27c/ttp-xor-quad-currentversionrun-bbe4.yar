rule TTP_XOR_QUAD_CurrentVersionRun_bbe4 {
  strings:
    $key_bbe4 = { e8 8b [2] cc 85 [2] e7 a9 [2] c9 8b [2] dd 90 [2] d2 8a [2] cc 97 [2] ce 96 [2] d5 90 [2] c9 97 [2] d5 b8 }

  condition:
    any of them
}