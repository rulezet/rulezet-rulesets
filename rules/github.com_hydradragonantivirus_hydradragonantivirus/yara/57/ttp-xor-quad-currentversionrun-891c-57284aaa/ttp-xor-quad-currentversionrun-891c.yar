rule TTP_XOR_QUAD_CurrentVersionRun_891c {
  strings:
    $key_891c = { da 73 [2] fe 7d [2] d5 51 [2] fb 73 [2] ef 68 [2] e0 72 [2] fe 6f [2] fc 6e [2] e7 68 [2] fb 6f [2] e7 40 }

  condition:
    any of them
}