rule TTP_XOR_QUAD_CurrentVersionRun_8910 {
  strings:
    $key_8910 = { da 7f [2] fe 71 [2] d5 5d [2] fb 7f [2] ef 64 [2] e0 7e [2] fe 63 [2] fc 62 [2] e7 64 [2] fb 63 [2] e7 4c }

  condition:
    any of them
}