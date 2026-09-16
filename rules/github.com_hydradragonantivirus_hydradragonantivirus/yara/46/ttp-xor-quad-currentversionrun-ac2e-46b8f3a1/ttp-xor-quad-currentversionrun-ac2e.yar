rule TTP_XOR_QUAD_CurrentVersionRun_ac2e {
  strings:
    $key_ac2e = { ff 41 [2] db 4f [2] f0 63 [2] de 41 [2] ca 5a [2] c5 40 [2] db 5d [2] d9 5c [2] c2 5a [2] de 5d [2] c2 72 }

  condition:
    any of them
}