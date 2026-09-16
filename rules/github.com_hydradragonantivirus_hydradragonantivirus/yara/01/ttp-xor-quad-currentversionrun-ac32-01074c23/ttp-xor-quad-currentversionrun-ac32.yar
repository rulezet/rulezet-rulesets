rule TTP_XOR_QUAD_CurrentVersionRun_ac32 {
  strings:
    $key_ac32 = { ff 5d [2] db 53 [2] f0 7f [2] de 5d [2] ca 46 [2] c5 5c [2] db 41 [2] d9 40 [2] c2 46 [2] de 41 [2] c2 6e }

  condition:
    any of them
}