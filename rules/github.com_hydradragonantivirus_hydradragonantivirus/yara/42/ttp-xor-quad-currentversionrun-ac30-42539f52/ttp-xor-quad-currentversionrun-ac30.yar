rule TTP_XOR_QUAD_CurrentVersionRun_ac30 {
  strings:
    $key_ac30 = { ff 5f [2] db 51 [2] f0 7d [2] de 5f [2] ca 44 [2] c5 5e [2] db 43 [2] d9 42 [2] c2 44 [2] de 43 [2] c2 6c }

  condition:
    any of them
}