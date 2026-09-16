rule TTP_XOR_QUAD_CurrentVersionRun_ac28 {
  strings:
    $key_ac28 = { ff 47 [2] db 49 [2] f0 65 [2] de 47 [2] ca 5c [2] c5 46 [2] db 5b [2] d9 5a [2] c2 5c [2] de 5b [2] c2 74 }

  condition:
    any of them
}