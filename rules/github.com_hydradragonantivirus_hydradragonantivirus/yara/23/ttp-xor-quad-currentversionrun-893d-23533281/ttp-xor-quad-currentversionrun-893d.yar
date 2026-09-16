rule TTP_XOR_QUAD_CurrentVersionRun_893d {
  strings:
    $key_893d = { da 52 [2] fe 5c [2] d5 70 [2] fb 52 [2] ef 49 [2] e0 53 [2] fe 4e [2] fc 4f [2] e7 49 [2] fb 4e [2] e7 61 }

  condition:
    any of them
}