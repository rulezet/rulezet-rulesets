rule TTP_XOR_QUAD_CurrentVersionRun_890a {
  strings:
    $key_890a = { da 65 [2] fe 6b [2] d5 47 [2] fb 65 [2] ef 7e [2] e0 64 [2] fe 79 [2] fc 78 [2] e7 7e [2] fb 79 [2] e7 56 }

  condition:
    any of them
}