rule TTP_XOR_QUAD_CurrentVersionRun_8bf6 {
  strings:
    $key_8bf6 = { d8 99 [2] fc 97 [2] d7 bb [2] f9 99 [2] ed 82 [2] e2 98 [2] fc 85 [2] fe 84 [2] e5 82 [2] f9 85 [2] e5 aa }

  condition:
    any of them
}