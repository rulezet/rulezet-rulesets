rule TTP_XOR_QUAD_CurrentVersionRun_8962 {
  strings:
    $key_8962 = { da 0d [2] fe 03 [2] d5 2f [2] fb 0d [2] ef 16 [2] e0 0c [2] fe 11 [2] fc 10 [2] e7 16 [2] fb 11 [2] e7 3e }

  condition:
    any of them
}