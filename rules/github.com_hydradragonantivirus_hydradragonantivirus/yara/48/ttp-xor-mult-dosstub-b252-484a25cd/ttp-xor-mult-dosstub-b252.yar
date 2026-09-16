rule TTP_XOR_MULT_DOSStub_b252 {
  strings:
    $key_b252 = { e6 3a [2] 92 22 [2] d5 20 [2] 92 31 [2] dc 3d [2] d0 37 [2] c7 3c [2] dc 72 [2] e1 }

  condition:
    any of them
}