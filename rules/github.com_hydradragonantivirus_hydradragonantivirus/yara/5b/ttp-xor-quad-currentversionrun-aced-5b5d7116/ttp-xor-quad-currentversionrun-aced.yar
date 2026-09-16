rule TTP_XOR_QUAD_CurrentVersionRun_aced {
  strings:
    $key_aced = { ff 82 [2] db 8c [2] f0 a0 [2] de 82 [2] ca 99 [2] c5 83 [2] db 9e [2] d9 9f [2] c2 99 [2] de 9e [2] c2 b1 }

  condition:
    any of them
}