rule TTP_XOR_QUAD_CurrentVersionRun_891d {
  strings:
    $key_891d = { da 72 [2] fe 7c [2] d5 50 [2] fb 72 [2] ef 69 [2] e0 73 [2] fe 6e [2] fc 6f [2] e7 69 [2] fb 6e [2] e7 41 }

  condition:
    any of them
}