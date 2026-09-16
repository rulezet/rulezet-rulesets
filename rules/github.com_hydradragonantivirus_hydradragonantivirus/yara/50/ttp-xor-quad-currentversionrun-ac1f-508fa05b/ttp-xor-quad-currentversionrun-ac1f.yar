rule TTP_XOR_QUAD_CurrentVersionRun_ac1f {
  strings:
    $key_ac1f = { ff 70 [2] db 7e [2] f0 52 [2] de 70 [2] ca 6b [2] c5 71 [2] db 6c [2] d9 6d [2] c2 6b [2] de 6c [2] c2 43 }

  condition:
    any of them
}