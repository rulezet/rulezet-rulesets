rule TTP_XOR_QUAD_CurrentVersionRun_89e1 {
  strings:
    $key_89e1 = { da 8e [2] fe 80 [2] d5 ac [2] fb 8e [2] ef 95 [2] e0 8f [2] fe 92 [2] fc 93 [2] e7 95 [2] fb 92 [2] e7 bd }

  condition:
    any of them
}