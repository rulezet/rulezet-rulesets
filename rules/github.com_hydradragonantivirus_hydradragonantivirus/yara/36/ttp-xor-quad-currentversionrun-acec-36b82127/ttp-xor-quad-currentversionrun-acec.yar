rule TTP_XOR_QUAD_CurrentVersionRun_acec {
  strings:
    $key_acec = { ff 83 [2] db 8d [2] f0 a1 [2] de 83 [2] ca 98 [2] c5 82 [2] db 9f [2] d9 9e [2] c2 98 [2] de 9f [2] c2 b0 }

  condition:
    any of them
}