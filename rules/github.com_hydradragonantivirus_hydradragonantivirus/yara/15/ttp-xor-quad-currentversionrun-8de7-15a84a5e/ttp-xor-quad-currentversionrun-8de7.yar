rule TTP_XOR_QUAD_CurrentVersionRun_8de7 {
  strings:
    $key_8de7 = { de 88 [2] fa 86 [2] d1 aa [2] ff 88 [2] eb 93 [2] e4 89 [2] fa 94 [2] f8 95 [2] e3 93 [2] ff 94 [2] e3 bb }

  condition:
    any of them
}