rule TTP_XOR_QUAD_CurrentVersionRun_8930 {
  strings:
    $key_8930 = { da 5f [2] fe 51 [2] d5 7d [2] fb 5f [2] ef 44 [2] e0 5e [2] fe 43 [2] fc 42 [2] e7 44 [2] fb 43 [2] e7 6c }

  condition:
    any of them
}