rule TTP_XOR_QUAD_CurrentVersionRun_8be1 {
  strings:
    $key_8be1 = { d8 8e [2] fc 80 [2] d7 ac [2] f9 8e [2] ed 95 [2] e2 8f [2] fc 92 [2] fe 93 [2] e5 95 [2] f9 92 [2] e5 bd }

  condition:
    any of them
}