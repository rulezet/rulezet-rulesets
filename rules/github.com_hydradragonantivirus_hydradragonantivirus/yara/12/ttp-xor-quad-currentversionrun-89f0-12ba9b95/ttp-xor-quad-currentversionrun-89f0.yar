rule TTP_XOR_QUAD_CurrentVersionRun_89f0 {
  strings:
    $key_89f0 = { da 9f [2] fe 91 [2] d5 bd [2] fb 9f [2] ef 84 [2] e0 9e [2] fe 83 [2] fc 82 [2] e7 84 [2] fb 83 [2] e7 ac }

  condition:
    any of them
}