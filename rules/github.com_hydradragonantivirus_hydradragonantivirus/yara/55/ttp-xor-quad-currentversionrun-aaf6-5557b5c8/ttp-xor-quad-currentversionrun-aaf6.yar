rule TTP_XOR_QUAD_CurrentVersionRun_aaf6 {
  strings:
    $key_aaf6 = { f9 99 [2] dd 97 [2] f6 bb [2] d8 99 [2] cc 82 [2] c3 98 [2] dd 85 [2] df 84 [2] c4 82 [2] d8 85 [2] c4 aa }

  condition:
    any of them
}