rule TTP_XOR_QUAD_CurrentVersionRun_aafe {
  strings:
    $key_aafe = { f9 91 [2] dd 9f [2] f6 b3 [2] d8 91 [2] cc 8a [2] c3 90 [2] dd 8d [2] df 8c [2] c4 8a [2] d8 8d [2] c4 a2 }

  condition:
    any of them
}