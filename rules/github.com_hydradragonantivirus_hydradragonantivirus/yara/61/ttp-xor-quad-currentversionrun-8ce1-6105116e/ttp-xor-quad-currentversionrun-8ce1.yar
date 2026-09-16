rule TTP_XOR_QUAD_CurrentVersionRun_8ce1 {
  strings:
    $key_8ce1 = { df 8e [2] fb 80 [2] d0 ac [2] fe 8e [2] ea 95 [2] e5 8f [2] fb 92 [2] f9 93 [2] e2 95 [2] fe 92 [2] e2 bd }

  condition:
    any of them
}