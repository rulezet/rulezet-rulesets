rule TTP_XOR_QUAD_CurrentVersionRun_ac12 {
  strings:
    $key_ac12 = { ff 7d [2] db 73 [2] f0 5f [2] de 7d [2] ca 66 [2] c5 7c [2] db 61 [2] d9 60 [2] c2 66 [2] de 61 [2] c2 4e }

  condition:
    any of them
}