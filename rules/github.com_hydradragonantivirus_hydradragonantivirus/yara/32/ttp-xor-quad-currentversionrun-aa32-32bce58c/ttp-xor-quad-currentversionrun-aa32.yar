rule TTP_XOR_QUAD_CurrentVersionRun_aa32 {
  strings:
    $key_aa32 = { f9 5d [2] dd 53 [2] f6 7f [2] d8 5d [2] cc 46 [2] c3 5c [2] dd 41 [2] df 40 [2] c4 46 [2] d8 41 [2] c4 6e }

  condition:
    any of them
}