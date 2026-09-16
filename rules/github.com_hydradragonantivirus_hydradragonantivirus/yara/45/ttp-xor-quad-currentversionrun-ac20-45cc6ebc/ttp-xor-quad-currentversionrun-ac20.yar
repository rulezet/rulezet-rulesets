rule TTP_XOR_QUAD_CurrentVersionRun_ac20 {
  strings:
    $key_ac20 = { ff 4f [2] db 41 [2] f0 6d [2] de 4f [2] ca 54 [2] c5 4e [2] db 53 [2] d9 52 [2] c2 54 [2] de 53 [2] c2 7c }

  condition:
    any of them
}