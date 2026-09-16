rule TTP_XOR_MULT_DOSStub_b24f {
  strings:
    $key_b24f = { e6 27 [2] 92 3f [2] d5 3d [2] 92 2c [2] dc 20 [2] d0 2a [2] c7 21 [2] dc 6f [2] e1 }

  condition:
    any of them
}