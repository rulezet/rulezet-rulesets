rule TTP_XOR_QUAD_CurrentVersionRun_aaeb {
  strings:
    $key_aaeb = { f9 84 [2] dd 8a [2] f6 a6 [2] d8 84 [2] cc 9f [2] c3 85 [2] dd 98 [2] df 99 [2] c4 9f [2] d8 98 [2] c4 b7 }

  condition:
    any of them
}