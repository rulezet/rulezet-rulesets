rule TTP_XOR_QUAD_CurrentVersionRun_aa0c {
  strings:
    $key_aa0c = { f9 63 [2] dd 6d [2] f6 41 [2] d8 63 [2] cc 78 [2] c3 62 [2] dd 7f [2] df 7e [2] c4 78 [2] d8 7f [2] c4 50 }

  condition:
    any of them
}