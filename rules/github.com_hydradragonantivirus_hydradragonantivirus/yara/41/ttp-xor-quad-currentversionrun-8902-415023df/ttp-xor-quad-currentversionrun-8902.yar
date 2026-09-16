rule TTP_XOR_QUAD_CurrentVersionRun_8902 {
  strings:
    $key_8902 = { da 6d [2] fe 63 [2] d5 4f [2] fb 6d [2] ef 76 [2] e0 6c [2] fe 71 [2] fc 70 [2] e7 76 [2] fb 71 [2] e7 5e }

  condition:
    any of them
}