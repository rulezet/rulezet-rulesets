rule TTP_XOR_QUAD_CurrentVersionRun_92e1 {
  strings:
    $key_92e1 = { c1 8e [2] e5 80 [2] ce ac [2] e0 8e [2] f4 95 [2] fb 8f [2] e5 92 [2] e7 93 [2] fc 95 [2] e0 92 [2] fc bd }

  condition:
    any of them
}