rule TTP_XOR_QUAD_CurrentVersionRun_ace7 {
  strings:
    $key_ace7 = { ff 88 [2] db 86 [2] f0 aa [2] de 88 [2] ca 93 [2] c5 89 [2] db 94 [2] d9 95 [2] c2 93 [2] de 94 [2] c2 bb }

  condition:
    any of them
}