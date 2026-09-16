rule TTP_XOR_QUAD_CurrentVersionRun_aae0 {
  strings:
    $key_aae0 = { f9 8f [2] dd 81 [2] f6 ad [2] d8 8f [2] cc 94 [2] c3 8e [2] dd 93 [2] df 92 [2] c4 94 [2] d8 93 [2] c4 bc }

  condition:
    any of them
}