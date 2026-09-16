rule TTP_XOR_QUAD_CurrentVersionRun_88c7 {
  strings:
    $key_88c7 = { db a8 [2] ff a6 [2] d4 8a [2] fa a8 [2] ee b3 [2] e1 a9 [2] ff b4 [2] fd b5 [2] e6 b3 [2] fa b4 [2] e6 9b }

  condition:
    any of them
}