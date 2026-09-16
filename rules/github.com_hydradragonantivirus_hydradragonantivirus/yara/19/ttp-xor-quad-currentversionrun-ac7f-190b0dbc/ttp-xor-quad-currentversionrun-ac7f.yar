rule TTP_XOR_QUAD_CurrentVersionRun_ac7f {
  strings:
    $key_ac7f = { ff 10 [2] db 1e [2] f0 32 [2] de 10 [2] ca 0b [2] c5 11 [2] db 0c [2] d9 0d [2] c2 0b [2] de 0c [2] c2 23 }

  condition:
    any of them
}