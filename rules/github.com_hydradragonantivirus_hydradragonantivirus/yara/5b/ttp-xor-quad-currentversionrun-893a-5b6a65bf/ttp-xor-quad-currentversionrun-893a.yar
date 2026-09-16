rule TTP_XOR_QUAD_CurrentVersionRun_893a {
  strings:
    $key_893a = { da 55 [2] fe 5b [2] d5 77 [2] fb 55 [2] ef 4e [2] e0 54 [2] fe 49 [2] fc 48 [2] e7 4e [2] fb 49 [2] e7 66 }

  condition:
    any of them
}