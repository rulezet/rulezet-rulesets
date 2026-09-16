rule TTP_XOR_QUAD_CurrentVersionRun_aaf3 {
  strings:
    $key_aaf3 = { f9 9c [2] dd 92 [2] f6 be [2] d8 9c [2] cc 87 [2] c3 9d [2] dd 80 [2] df 81 [2] c4 87 [2] d8 80 [2] c4 af }

  condition:
    any of them
}