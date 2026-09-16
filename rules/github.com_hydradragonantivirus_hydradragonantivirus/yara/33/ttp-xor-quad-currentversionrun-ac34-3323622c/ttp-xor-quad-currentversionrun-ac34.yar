rule TTP_XOR_QUAD_CurrentVersionRun_ac34 {
  strings:
    $key_ac34 = { ff 5b [2] db 55 [2] f0 79 [2] de 5b [2] ca 40 [2] c5 5a [2] db 47 [2] d9 46 [2] c2 40 [2] de 47 [2] c2 68 }

  condition:
    any of them
}