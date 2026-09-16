rule TTP_XOR_QUAD_CurrentVersionRun_aa21 {
  strings:
    $key_aa21 = { f9 4e [2] dd 40 [2] f6 6c [2] d8 4e [2] cc 55 [2] c3 4f [2] dd 52 [2] df 53 [2] c4 55 [2] d8 52 [2] c4 7d }

  condition:
    any of them
}