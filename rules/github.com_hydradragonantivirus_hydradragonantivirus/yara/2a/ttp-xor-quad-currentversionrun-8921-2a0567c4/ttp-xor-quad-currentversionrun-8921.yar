rule TTP_XOR_QUAD_CurrentVersionRun_8921 {
  strings:
    $key_8921 = { da 4e [2] fe 40 [2] d5 6c [2] fb 4e [2] ef 55 [2] e0 4f [2] fe 52 [2] fc 53 [2] e7 55 [2] fb 52 [2] e7 7d }

  condition:
    any of them
}