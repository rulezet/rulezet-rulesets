rule TTP_XOR_QUAD_CurrentVersionRun_899a {
  strings:
    $key_899a = { da f5 [2] fe fb [2] d5 d7 [2] fb f5 [2] ef ee [2] e0 f4 [2] fe e9 [2] fc e8 [2] e7 ee [2] fb e9 [2] e7 c6 }

  condition:
    any of them
}