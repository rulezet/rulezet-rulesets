rule TTP_XOR_QUAD_CurrentVersionRun_aaf1 {
  strings:
    $key_aaf1 = { f9 9e [2] dd 90 [2] f6 bc [2] d8 9e [2] cc 85 [2] c3 9f [2] dd 82 [2] df 83 [2] c4 85 [2] d8 82 [2] c4 ad }

  condition:
    any of them
}