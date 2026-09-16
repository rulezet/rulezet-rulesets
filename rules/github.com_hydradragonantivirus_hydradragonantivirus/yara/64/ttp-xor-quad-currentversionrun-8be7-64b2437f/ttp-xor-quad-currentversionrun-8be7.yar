rule TTP_XOR_QUAD_CurrentVersionRun_8be7 {
  strings:
    $key_8be7 = { d8 88 [2] fc 86 [2] d7 aa [2] f9 88 [2] ed 93 [2] e2 89 [2] fc 94 [2] fe 95 [2] e5 93 [2] f9 94 [2] e5 bb }

  condition:
    any of them
}